FROM registry.access.redhat.com/rhel7:latest
COPY admissioncontroller /usr/local/bin/
ENTRYPOINT ["admissioncontroller"]
