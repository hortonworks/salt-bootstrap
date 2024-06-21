#! /bin/bash
set -x

rm -rf release
mkdir release
cd release || exit 1

declare -a Platforms=("Linux_x86_64" "Darwin_x86_64" "Linux_arm64")
for platform in "${Platforms[@]}"; do
  if [ -d "../build/$platform" ]; then
    echo "Compressing the ${platform} relevant binary ..."
    RELEASE="${BINARY}_${VERSION}_${platform}.tgz"
    tar -zcf "$RELEASE" -C ../build/$platform $BINARY
    sha256sum "$RELEASE" >> "${RELEASE}.sha256"
  fi
done

echo "Creating release v${VERSION} from branch $BRANCH ..."

output=$(gh release list | grep ${VERSION})
if [ -z "$output" ]; then
  gh release create "v${VERSION}" ./* -t ${VERSION} -n ""
else
  echo "The cli release ${VERSION} already exists on the github."
fi
