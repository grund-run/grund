FROM busybox:1.37.0
COPY entrypoint.sh /run-entrypoint
RUN chmod 0555 /run-entrypoint
ENTRYPOINT ["/run-entrypoint"]
CMD ["serve"]
