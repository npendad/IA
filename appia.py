import os
import joblib
import pefile
import pandas as pd
import streamlit as st
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score

# Chemin vers le modèle sauvegardé
MODEL_PATH = 'random_forest_model.pkl'

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model():
    """Entraîner et sauvegarder le modèle."""
    st.info("⏳ Entraînement du modèle en cours...")
    
    # Chargement des données
    data = pd.read_csv("DatasetmalwareExtrait.csv")
    X = data.drop(['legitimate'], axis=1)
    y = data['legitimate']

    # Entraînement du modèle
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(
        n_estimators=196, random_state=42, criterion="gini",
        max_depth=25, min_samples_split=4, min_samples_leaf=1
    )
    model.fit(X_train, y_train)

    # Évaluation du modèle
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred, average='weighted')

    st.success(f"Modèle entraîné avec succès. Précision : {accuracy:.3f}, Rappel : {recall:.3f}")
    
    # Sauvegarde du modèle
    joblib.dump(model, MODEL_PATH)
    return model

# Chargement ou entraînement du modèle
if os.path.exists(MODEL_PATH):
    st.info("🔄 Chargement du modèle existant...")
    model = joblib.load(MODEL_PATH)
else:
    model = train_and_save_model()

# Fonction pour calculer le hash d'un fichier
def calculate_file_hash(file_path):
    """Calculer le hash SHA-256 du fichier."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Fonction pour extraire les attributs PE
def extract_pe_attributes(file_path):
    """Extraction des attributs du fichier PE."""
    try:
        pe = pefile.PE(file_path)
        attributes = {
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'ResourceSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        }
        return attributes
    except Exception as e:
        st.error(f"Erreur lors de l'extraction des attributs PE : {str(e)}")
        return {"Erreur": str(e)}

# Fonction de prédiction
def predict_malware(file):
    """Prédiction de malware."""
    try:
        # Sauvegarde temporaire du fichier
        temp_file = f"temp_{file.name}"
        with open(temp_file, "wb") as f:
            f.write(file.read())

        # Extraction des attributs
        attributes = extract_pe_attributes(temp_file)
        if "Erreur" in attributes:
            return attributes["Erreur"]

        # Conversion en DataFrame
        df = pd.DataFrame([attributes])

        # Prédiction
        prediction = model.predict(df)
        proba = model.predict_proba(df)[0]

        # Résultat
        if prediction[0] == 1:
            result = f"🚨 Malware détecté (Probabilité : {proba[1] * 100:.2f}%)"
        else:
            result = f"✅ Fichier légitime (Probabilité : {proba[0] * 100:.2f}%)"

        # Suppression du fichier temporaire
        os.remove(temp_file)

        return result
    except Exception as e:
        return f"Erreur lors de l'analyse : {str(e)}"

# Interface Streamlit
st.title("🛡️ Détecteur de Malwares")
st.write("Analysez vos fichiers exécutables (.exe, .dll, .sys) pour détecter les menaces potentielles.")

# Téléchargement de fichier
uploaded_file = st.file_uploader("Téléchargez un fichier exécutable à analyser", type=["exe", "dll", "sys"])

if uploaded_file is not None:
    st.info("⏳ Analyse en cours...")
    result = predict_malware(uploaded_file)
    st.success(result)
