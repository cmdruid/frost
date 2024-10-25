#!/bin/bash

DIRECTORY="./dist"
EXTENSIONS=("js" "ts")   # The file extensions to target. Add more extensions as needed.
ABSOLUTE_PATH="@/"       # The path we are replacing.
DEPTH_OFFSET=3           # The offset for our depth counter.

# Clean the existing dist directory.
rm -rf "$DIRECTORY"
mkdir -p "$DIRECTORY"

# Copy and format the package.json file.
cp package.json $DIRECTORY/package.json
sed -i "s#$DIRECTORY#.#g" "$DIRECTORY/package.json"

# Build the current project source using tsc and rollup.
yarn tsc

if [ $? -ne 0 ]; then
    echo "TypeScript build failed."
    exit 1
fi

yarn rollup -c rollup.config.ts --configPlugin typescript

if [ $? -ne 0 ]; then
    echo "Rollup build failed."
    exit 1
fi

# Resolve path aliases in files by adjusting for file depth.
for EXTENSION in "${EXTENSIONS[@]}"
do
    # Loop through all files in the directory that match the current extension.
    find "$DIRECTORY" -name "*.$EXTENSION" -type f | while read -r file
    do
        # Count the number of slashes in the file's path to determine its depth
        DEPTH=$(echo "$file" | tr -cd '/' | wc -c)

        # Build a relative path string based on the depth.
        RELATIVE_PATH=""
        for (( i=DEPTH_OFFSET; i<=$DEPTH; i++ ))
        do
            RELATIVE_PATH="../$RELATIVE_PATH"
        done

        # Determine if we are on macOS or Linux, and use the appropriate sed syntax.
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS sed syntax
            sed -i '' "s|$ABSOLUTE_PATH|$RELATIVE_PATH|g" "$file"
        else
            # Linux sed syntax
            sed -i "s|$ABSOLUTE_PATH|$RELATIVE_PATH|g" "$file"
        fi
    done
done

echo "Build completed successfully."
