#! /bin/bash
set -x

rm -rf release
mkdir release

ARCH=$(uname -m)

declare -a Platforms=("Linux" "Darwin")
for platform in ${Platforms[@]}; do
  if [ -d "./build/$platform" ]; then
    echo "Compressing the ${platform} relevant binary ..."
    tar -zcf "release/${BINARY}_${VERSION}_${platform}_${ARCH}.tgz" -C build/$platform $BINARY
  fi
done

echo "Creating release v${VERSION} from branch $BRANCH ..."

output=$(gh release list | grep ${VERSION})
if [ -z "$output" ]; then
  gh release create "v${VERSION}" "./release/${BINARY}_${VERSION}_Linux_${ARCH}.tgz" "./release/${BINARY}_${VERSION}_Darwin_${ARCH}.tgz" -t ${VERSION} -n ""
else
  echo "The cli release ${VERSION} already exists on the github."
fi
