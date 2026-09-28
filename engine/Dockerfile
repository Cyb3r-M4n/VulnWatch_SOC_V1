# engine/Dockerfile
# Image de base Python 3.11 slim
FROM python:3.11-slim

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier les dépendances Python
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY src/ ./src/

# Créer les dossiers pour les données et les rapports
RUN mkdir -p /app/data /app/reports

# Exposer le port
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
