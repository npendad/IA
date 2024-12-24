import os
import joblib
import pefile
import numpy as np
import pandas as pd
import streamlit as st
import hashlib
import traceback
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score

# Chemin vers le modèle sauvegardé
MODEL_PATH = 'random_forest_model.pkl'

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model():
    st.info("Aucun modèle trouvé. Entraînement du modèle en cours...")
    data = pd.read_csv("DatasetmalwareExtrait.csv")
    X = data.drop(['legitimate'], axis=1)
    y = data['legitimate']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(
        n_estimators=196, random_state=42, criterion="gini",
        max_depth=25, min_samples_split=4, min_samples_leaf=1
    )
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred, average='weighted')
    
    st.success(f"Modèle entraîné avec succès. Précision : {accuracy:.3f}, Rappel : {recall:.3f}")
    joblib.dump(model, MODEL_PATH)
    st.info(f"Modèle sauvegardé sous : {MODEL_PATH}")
    return model

# Chargement ou entraînement du modèle
if os.path.exists(MODEL_PATH):
    st.info("Chargement du modèle existant...")
    model = joblib.load(MODEL_PATH)
else:
    model = train_and_save_model()

# Fonction pour calculer le hash d'un fichier
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Fonction pour extraire les attributs PE
def extract_pe_attributes(file_path):
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
        st.error(f"Erreur de traitement du fichier : {str(e)}")
        return {"Erreur": str(e)}

# Fonction de prédiction
def predict_malware(file):
    if model is None:
        return "Erreur : Modèle non chargé"

    try:
        temp_file = f"temp_{file.name}"
        with open(temp_file, "wb") as f:
            f.write(file.read())

        attributes = extract_pe_attributes(temp_file)
        if "Erreur" in attributes:
            return attributes["Erreur"]

        df = pd.DataFrame([attributes])
        prediction = model.predict(df)
        proba = model.predict_proba(df)[0]

        os.remove(temp_file)
        return prediction[0], proba
    except Exception as e:
        return f"Erreur d'analyse : {str(e)}"

# Interface utilisateur Streamlit
st.title("🛡️ Détecteur de Malwares")
st.write("Téléchargez un fichier exécutable pour analyser s'il est légitime ou un malware.")

uploaded_file = st.file_uploader("Télécharger un fichier exécutable (.exe, .dll, .sys)", type=["exe", "dll", "sys"])

if uploaded_file is not None:
    st.info("Analyse en cours...")
    result = predict_malware(uploaded_file)

    if isinstance(result, tuple):
        prediction, proba = result
        col1, col2 = st.columns(2)
        
        if prediction == 1:
            col1.error(f"🚨 **MALWARE détecté !**")
            col2.metric("Probabilité de Malware", f"{proba[1] * 100:.2f}%")
        else:
            col1.success(f"✅ **Fichier légitime !**")
            col2.metric("Probabilité de légitimité", f"{proba[0] * 100:.2f}%")
        
        # Affichage graphique des probabilités
        labels = ['Légitime', 'Malware']
        plt.figure(figsize=(4, 4))
        plt.bar(labels, proba, color=['green', 'red'])
        plt.title("Probabilités de classification")
        plt.ylabel("Probabilité")
        st.pyplot(plt)
    else:
        st.error(result)
