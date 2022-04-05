#!/bin/sh

# This works around the error:
#
#	Error while loading /usr/local/sbin/dpkg-split: No such file or directory
#
# Which can occur when using `docker buildx` to perform multi-architecture
# builds in GitHub Actions.
#
# See: https://github.com/docker/buildx/issues/495#issuecomment-761562905
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
docker buildx create --name multiarch --driver docker-container --use
docker buildx inspect --bootstrap
