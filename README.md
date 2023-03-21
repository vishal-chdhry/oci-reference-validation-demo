## Requirements

- Docker
- ORAS CLI
- Go 1.19+

## Setup
1. Setup Environment variables
   ```
   export PORT=5000
   export REGISTRY=localhost:${PORT}
   export REPO=${REGISTRY}/lachie/net-monitor
   export IMAGE=${REPO}:v1
   ```
2. Start a local instance of CNCF container registry
   ```
   docker run -d -p ${PORT}:5000 ghcr.io/oras-project/registry:v1.0.0-rc.4
   ```

3. Build the image and push it to the CNCF container registory
   ```
   docker build -t $IMAGE https://github.com/wabbit-networks/net-monitor.git#main
   docker push $IMAGE
   ```
4. Sign the image using notation
   ```
   notation sign --signature-format cose $IMAGE
   ```
5. Add an SBOM to the image
   ```
   syft packages -q "$IMAGE" -o cyclonedx-json \
   | regctl artifact put --subject "$IMAGE" \
      --artifact-type application/vnd.cyclonedx+json \
      -m application/vnd.cyclonedx+json \
      --annotation "org.opencontainers.artifact.description=CycloneDX JSON SBOM"
   ```
6. Find the digest of the SBOM
   ```
   regctl artifact list $IMAGE
   ```
7. Sign the SBOM attached to the image 
   ```
   notation sign --signature-format cose ${REPO}@<DIGEST-OF-THE-SBOM> 
   ```