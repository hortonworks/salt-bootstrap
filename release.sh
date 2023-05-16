#! /bin/bash
set -x

rm -rf release
mkdir release

declare -a Platforms=("Linux_x86_64" "Darwin_x86_64" "Linux_arm64")
for platform in "${Platforms[@]}"; do
  if [ -d "./build/$platform" ]; then
    echo "Compressing the ${platform} relevant binary ..."
    tar -zcf "release/${BINARY}_${VERSION}_${platform}.tgz" -C build/$platform $BINARY
  fi
done

echo "Creating release v${VERSION} from branch $BRANCH ..."

output=$(gh release list | grep ${VERSION})
if [ -z "$output" ]; then
  gh release create "v${VERSION}" ./release/*.tgz -t ${VERSION} -n ""
else
  echo "The cli release ${VERSION} already exists on the github."
fi
