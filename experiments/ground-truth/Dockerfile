# Ground-truth experiment image: the demo image plus the toolchains whose own
# bookkeeping serves as the reference instrument (rustc dep-info, go module
# stamps).  The project image is left alone; nothing here belongs in it.
#
# Build (from the repository root):
#   docker build -t build-recorder:ground-truth -f experiments/ground-truth/Dockerfile .
FROM build-recorder:latest

RUN apt-get update -q && \
    apt-get install -y -q \
        rpm-macros-rust \
        rpm-build-rust \
        rpm-build-golang \
        rpm-build-vim \
        golang && \
    apt-get clean

COPY experiments/ground-truth/cc-wrapper.sh /experiment/cc-wrapper.sh
COPY experiments/ground-truth/run-build.sh /experiment/run-build.sh
RUN chmod +x /experiment/cc-wrapper.sh /experiment/run-build.sh

ENTRYPOINT ["/experiment/run-build.sh"]
