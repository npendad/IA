import os
import joblib
import pefile
import numpy as np
import pandas as pd
import streamlit as st
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score


# Constantes
MODEL_PATH = 'random_forest_model.pkl'
FEATURES_LIST = [
    'AddressOfEntryPoint', 'MajorLinkerVersion', 'MajorImageVersion', 
    'MajorOperatingSystemVersion', 'DllCharacteristics', 'SizeOfStackReserve', 'NumberOfSections'
]

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model():
    """Entraîner et sauvegarder un modèle RandomForestClassifier."""
    st.write("Entraînement du modèle, cela peut prendre un moment...")
    
    # Chargement des données
    data = pd.read_csv("DatasetmalwareExtrait.csv")
    X = data.drop(['legitimate'], axis=1)
    y = data['legitimate']

    # Entraînement du modèle
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(
        n_estimators=196, random_state=42, criterion="gini", max_depth=25, 
        min_samples_split=4, min_samples_leaf=1
    )
    model.fit(X_train, y_train)

    # Évaluation du modèle
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred, average='weighted')

    st.write(f"Précision du modèle : {accuracy:.3f}")
    st.write(f"Rappel du modèle : {recall:.3f}")

    # Sauvegarde du modèle
    joblib.dump(model, MODEL_PATH)
    st.write(f"Modèle sauvegardé sous : {MODEL_PATH}")
    return model

# Chargement du modèle ou entraînement si nécessaire
def load_or_train_model():
    """Charger le modèle si existant, sinon entraîner et sauvegarder."""
    if os.path.exists(MODEL_PATH):
        st.write("Chargement du modèle existant...")
        return joblib.load(MODEL_PATH)
    else:
        return train_and_save_model()

# Fonction pour extraire les attributs PE
def extract_pe_attributes(file_path):
    """Extraire les 7 caractéristiques du fichier PE."""
    try:
        pe = pefile.PE(file_path)
        attributes = {
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections
        }
        return attributes
    except Exception as e:
        st.error(f"Erreur lors de l'extraction des caractéristiques : {str(e)}")
        return None

# Fonction pour calculer le hash du fichier
def calculate_file_hash(file_path):
    """Calculer le hash SHA-256 du fichier pour vérification."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Fonction de prédiction
def predict_malware(file, model):
    """Effectuer une prédiction de malware sur le fichier."""
    if model is None:
        return "Erreur : Modèle non chargé"

    try:
        # Sauvegarde temporaire du fichier
        temp_file = f"temp_{file.name}"
        with open(temp_file, "wb") as f:
            f.write(file.read())

        # Extraire les caractéristiques du fichier PE
        features = extract_pe_attributes(temp_file)
        if features is None:
            os.remove(temp_file)
            return "Erreur lors de l'extraction des caractéristiques du fichier."

        # Convertir en DataFrame pour prédiction
        df = pd.DataFrame([features])

        # Faire la prédiction
        prediction = model.predict(df)
        proba = model.predict_proba(df)[0]

        # Résultat avec probabilité
        if prediction[0] == 1:
            result = f"🚨 MALWARE (Probabilité: {proba[1] * 100:.2f}%)"
        else:
            result = f"✅ Fichier Légitime (Probabilité: {proba[0] * 100:.2f}%)"

        # Suppression du fichier temporaire
        os.remove(temp_file)

        return result
    except Exception as e:
        return f"Erreur d'analyse : {str(e)}"

# Interface utilisateur Streamlit
def main():
    st.title("🛡️ Détecteur de Malwares")
    st.write("Téléchargez un fichier exécutable pour analyser s'il est légitime ou un malware.")

    # Charger ou entraîner le modèle
    model = load_or_train_model()

    # Téléchargement de fichier
    uploaded_file = st.file_uploader("Télécharger un fichier exécutable (.exe, .dll, .sys)", type=["exe", "dll", "sys"])

    if uploaded_file is not None:
        st.write("Analyse en cours...")
        result = predict_malware(uploaded_file, model)
        st.success(result)

if __name__ == "__main__":
    main()
