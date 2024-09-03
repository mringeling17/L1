# Usa la imagen base de Ubuntu
FROM ubuntu:latest

# Establece el directorio de trabajo
WORKDIR /app

# Instala Python y pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copia los archivos de la aplicación al contenedor
COPY . .

# Mantiene el contenedor en ejecución indefinidamente
CMD ["tail", "-f", "/dev/null"]