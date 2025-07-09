# Base: GCC with Node.js 18
FROM gcc:13

# Install Node.js 18
RUN apt-get update && \
    apt-get install -y curl gnupg cmake make && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

WORKDIR /app

# Copy C++ source and build
COPY CMakeLists.txt .
COPY src/ ./src/
COPY include/ ./include/
COPY third_party/ ./third_party/

RUN cmake -S . -B build && cmake --build build -j

# Copy Node.js API
COPY ml-kem-api/package*.json ./ml-kem-api/
RUN cd ml-kem-api && npm install
COPY ml-kem-api/ ./ml-kem-api/

# Expose and run server
EXPOSE 3050
CMD ["node", "ml-kem-api/index.js"]
