#!/bin/bash

# Configuration
DIRECTORY="./dist"
EXTENSIONS=("js" "ts")   # The file extensions to target. Add more extensions as needed.
ABSOLUTE_PATH="@/"       # The path we are replacing.
DEPTH_OFFSET=3           # The offset for our depth counter.

# Helper function to clean and prepare the dist directory
clean_dist_directory() {
  echo "Cleaning dist directory..."
  rm -rf "$DIRECTORY"
  mkdir -p "$DIRECTORY"
}

# Helper function to prepare package.json
prepare_package_json() {
  echo "Preparing package.json..."
  cp package.json "$DIRECTORY/package.json"
  sed -i "s#$DIRECTORY#.#g" "$DIRECTORY/package.json"
}

# Helper function to run build tools
build_project() {
  echo "Running TypeScript compiler..."
  if ! npx tsc; then
    echo "TypeScript build failed."
    exit 1
  fi

  echo "Running Rollup bundler..."
  if ! npx rollup -c rollup.config.ts --configPlugin typescript; then
    echo "Rollup build failed."
    exit 1
  fi
}

# Helper function to get the appropriate sed command based on OS
get_sed_command() {
  local file="$1"
  local pattern="$2"
  local replacement="$3"

  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|$pattern|$replacement|g" "$file"
  else
    sed -i "s|$pattern|$replacement|g" "$file"
  fi
}

# Helper function to resolve path aliases
resolve_path_aliases() {
  echo "Resolving path aliases..."
  for EXTENSION in "${EXTENSIONS[@]}"; do
    find "$DIRECTORY" -name "*.$EXTENSION" -type f | while read -r file; do
      # Calculate depth and relative path
      DEPTH=$(echo "$file" | tr -cd '/' | wc -c)
      RELATIVE_PATH=""
      
      for (( i=DEPTH_OFFSET; i<=$DEPTH; i++ )); do
        RELATIVE_PATH="../$RELATIVE_PATH"
      done

      get_sed_command "$file" "$ABSOLUTE_PATH" "$RELATIVE_PATH"
    done
  done
}

# Main execution
main() {
  echo "Starting build process..."
  
  clean_dist_directory
  prepare_package_json
  build_project
  resolve_path_aliases
  
  echo "Build completed successfully."
}

# Run the script
main
