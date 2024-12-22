# Utiliser une image officielle Python comme base
FROM python:3.9-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier les fichiers nécessaires dans le conteneur
COPY . /app

# Installer les dépendances
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Exposer le port par défaut de Streamlit
EXPOSE 8501

# Définir la commande pour lancer l'application Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

