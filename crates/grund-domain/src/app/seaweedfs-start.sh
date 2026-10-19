: "${S3_ACCESS_KEY_ID:?S3_ACCESS_KEY_ID must be set}"
: "${S3_SECRET_ACCESS_KEY:?S3_SECRET_ACCESS_KEY must be set}"
# Native AWS environment credentials log the access key at normal verbosity.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
umask 077
config="$(mktemp /tmp/grund-s3.XXXXXX)"
awk '
function quote(value, result, i, c, n) {
    result = "\""
    for (i = 1; i <= length(value); i++) {
        c = substr(value, i, 1)
        if (c == "\\" || c == "\"") result = result "\\" c
        else if ((n = index(controls, c)) > 0) result = result sprintf("\\u%04x", n)
        else result = result c
    }
    return result "\""
}
BEGIN {
    for (i = 1; i < 32; i++) controls = controls sprintf("%c", i)
    printf "{\"identities\":[{\"name\":\"grund\",\"credentials\":[{\"accessKey\":%s,\"secretKey\":%s}],\"actions\":[\"Admin\"]}]}\n", quote(ENVIRON["S3_ACCESS_KEY_ID"]), quote(ENVIRON["S3_SECRET_ACCESS_KEY"])
}' > "$config"
chown seaweed:seaweed "$config"
exec /entrypoint.sh server \
    -s3 -s3.config="$config" -dir=/data \
    -ip=127.0.0.1 -ip.bind=127.0.0.1 -s3.ip.bind=0.0.0.0 \
    -master.volumeSizeLimitMB=1024 -volume.max=0 -volume.index=leveldb \
    -master.telemetry=false -s3.iam=false -s3.port.iceberg=0 -s3.port.lance=0 \
    -s3.autoCreateBucket=false -s3.allowDeleteBucketNotEmpty=false
