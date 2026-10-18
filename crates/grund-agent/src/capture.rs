use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

/// Bytes in each capture segment; four segments per stream bound local app output.
pub const SEGMENT_BYTES: u64 = 256 * 1024;
/// Retained segments per stream, including the current file.
pub const SEGMENTS: usize = 4;
const RETRY: Duration = Duration::from_secs(1);

struct Chunk {
    stream: usize,
    bytes: [u8; 4096],
    count: usize,
}

struct Output {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    rotate_pending: bool,
    retry_at: Instant,
}

impl Output {
    fn new(directory: &Path, stream: &str) -> Self {
        Self {
            path: directory.join(stream),
            file: None,
            bytes: 0,
            rotate_pending: true,
            retry_at: Instant::now(),
        }
    }

    fn segment(&self, n: usize) -> PathBuf {
        self.path.with_extension(n.to_string())
    }

    fn open(&mut self, now: Instant) -> bool {
        if now < self.retry_at {
            return false;
        }
        self.retry_at = now + RETRY;
        let Some(directory) = self.path.parent() else {
            return false;
        };
        if std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .is_err()
        {
            return false;
        }
        if self.rotate_pending {
            self.file = None;
            let _ = std::fs::remove_file(self.segment(SEGMENTS - 1));
            for n in (0..SEGMENTS - 1).rev() {
                let _ = std::fs::rename(self.segment(n), self.segment(n + 1));
            }
            self.rotate_pending = false;
        }
        let Ok(file) = OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(self.segment(0))
        else {
            return false;
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if !metadata.is_file() {
            return false;
        }
        self.bytes = metadata.len();
        self.file = Some(file);
        true
    }

    fn append_at(&mut self, bytes: &[u8], now: Instant) -> bool {
        if self.file.is_none() && !self.open(now) {
            return false;
        }
        if self.bytes + bytes.len() as u64 > SEGMENT_BYTES {
            self.file = None;
            self.rotate_pending = true;
            self.retry_at = now;
            if !self.open(now) {
                return false;
            }
        }
        match self.file.as_mut().map(|file| file.write_all(bytes)) {
            Some(Ok(())) => {
                self.bytes += bytes.len() as u64;
                true
            }
            _ => {
                self.file = None;
                self.retry_at = now + RETRY;
                false
            }
        }
    }
}

fn write_loss(directory: &Path, epoch: uuid::Uuid, count: u64) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let temporary = directory.join(".dropped-bytes");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&temporary)?;
    write!(file, "{epoch} {count}")?;
    file.sync_all()?;
    std::fs::rename(temporary, directory.join("dropped-bytes"))?;
    File::open(directory)?.sync_all()
}

fn write_chunks(directory: PathBuf, receiver: mpsc::Receiver<Chunk>, dropped: Arc<AtomicU64>) {
    let mut outputs = [
        Output::new(&directory, "stdout"),
        Output::new(&directory, "stderr"),
    ];
    let epoch = uuid::Uuid::now_v7();
    let mut reported = Instant::now()
        .checked_sub(RETRY)
        .unwrap_or_else(Instant::now);
    let mut persisted = None;
    loop {
        let received = if persisted == Some(dropped.load(Ordering::Relaxed)) {
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        } else {
            receiver.recv_timeout(RETRY)
        };
        match received {
            Ok(chunk) => {
                if !outputs[chunk.stream].append_at(&chunk.bytes[..chunk.count], Instant::now()) {
                    dropped.fetch_add(chunk.count as u64, Ordering::Relaxed);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let count = dropped.load(Ordering::Relaxed);
                if persisted != Some(count) {
                    let _ = write_loss(&directory, epoch, count);
                }
                return;
            }
        }
        if reported.elapsed() >= RETRY {
            let count = dropped.load(Ordering::Relaxed);
            if persisted != Some(count) && write_loss(&directory, epoch, count).is_ok() {
                persisted = Some(count);
            }
            reported = Instant::now();
        }
    }
}

fn run_streams(
    directory: &Path,
    mut inputs: [File; 2],
    ready: impl FnOnce(),
) -> anyhow::Result<()> {
    let dropped = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::sync_channel::<Chunk>(64);
    let output_directory = directory.to_path_buf();
    let losses = dropped.clone();
    let writer = std::thread::Builder::new()
        .name("app-capture-writer".into())
        .spawn(move || write_chunks(output_directory, receiver, losses))
        .ok();
    let mut poll = [
        libc::pollfd {
            fd: inputs[0].as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: inputs[1].as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    ready();
    let mut buffer = [0u8; 4096];
    while poll.iter().any(|fd| fd.fd >= 0) {
        let result = unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as libc::nfds_t, -1) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        for stream in 0..2 {
            if poll[stream].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            match inputs[stream].read(&mut buffer) {
                Ok(0) => poll[stream].fd = -1,
                Ok(count) => {
                    if sender
                        .try_send(Chunk {
                            stream,
                            bytes: buffer,
                            count,
                        })
                        .is_err()
                    {
                        dropped.fetch_add(count as u64, Ordering::Relaxed);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => poll[stream].fd = -1,
            }
        }
    }
    drop(sender);
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ok(())
}

/// Containerd binary logger: fd 3/4 are app streams; closing fd 5 signals readiness.
/// A polling pipe reader never waits for capture storage or network access. Missing
/// directories, full disks and exhausted inodes discard bytes and retry storage
/// at most once per second; they never close the app's output pipes.
pub fn run(directory: &Path) -> anyhow::Result<()> {
    for fd in 3..=5 {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        anyhow::ensure!(
            unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } == 0,
            "container logger descriptors are unavailable"
        );
        let metadata = unsafe { metadata.assume_init() };
        anyhow::ensure!(
            metadata.st_mode & libc::S_IFMT == libc::S_IFIFO,
            "container logger descriptors are not pipes"
        );
    }
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let inputs = unsafe { [File::from_raw_fd(3), File::from_raw_fd(4)] };
    let ready = unsafe { File::from_raw_fd(5) };
    run_streams(directory, inputs, || drop(ready))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_rotation_discards_oldest_without_growing_files() {
        let dir = std::env::temp_dir().join(format!("grund-capture-{}", uuid::Uuid::now_v7()));
        let mut output = Output::new(&dir, "stdout");
        for n in 0..10 {
            assert!(output.append_at(&vec![n; SEGMENT_BYTES as usize], Instant::now()));
        }
        assert_eq!(std::fs::read(output.segment(0)).unwrap()[0], 9);
        assert_eq!(std::fs::read(output.segment(3)).unwrap()[0], 6);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), SEGMENTS);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unavailable_capture_storage_recovers_without_restarting_the_app() {
        let dir =
            std::env::temp_dir().join(format!("grund-capture-recovery-{}", uuid::Uuid::now_v7()));
        std::fs::write(&dir, b"not a directory").unwrap();
        let now = Instant::now();
        let mut output = Output::new(&dir, "stdout");
        assert!(!output.append_at(b"lost", now));
        std::fs::remove_file(&dir).unwrap();
        assert!(output.append_at(b"recovered", now + RETRY * 2));
        output.file = Some(OpenOptions::new().write(true).open("/dev/full").unwrap());
        assert!(!output.append_at(b"lost", now + RETRY * 3));
        assert!(output.append_at(b" again", now + RETRY * 5));
        assert_eq!(
            std::fs::read(output.segment(0)).unwrap(),
            b"recovered again"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn both_app_streams_keep_writing_when_capture_directory_cannot_be_created() {
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        let dir =
            std::env::temp_dir().join(format!("grund-capture-drain-{}", uuid::Uuid::now_v7()));
        std::fs::write(&dir, b"not a directory").unwrap();
        let (mut out, out_read) = UnixStream::pair().unwrap();
        let (mut err, err_read) = UnixStream::pair().unwrap();
        out.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        err.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let directory = dir.clone();
        let reader = std::thread::spawn(move || {
            run_streams(
                &directory,
                [
                    File::from(OwnedFd::from(out_read)),
                    File::from(OwnedFd::from(err_read)),
                ],
                || {},
            )
        });
        let writer = std::thread::spawn(move || {
            err.write_all(&vec![b'e'; 1024 * 1024]).unwrap();
        });
        out.write_all(&vec![b'o'; 1024 * 1024]).unwrap();
        drop(out);
        writer.join().unwrap();
        reader.join().unwrap().unwrap();
        std::fs::remove_file(dir).unwrap();
    }
}
