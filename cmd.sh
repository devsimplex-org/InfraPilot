  # Builds ONLY backend
  ./scripts/build-and-publish.sh v1.0.0 --backend

  # Builds ALL four (including all-in-one)
  ./scripts/build-and-publish.sh v1.0.0

  To build only the all-in-one image using the root Dockerfile:
  ./scripts/build-and-publish.sh v1.0.0 --all-in-one

  Did the all-in-one build fail, or did you use one of the component flags?