import os
import joblib
import pandas as pd
import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix, classification_report

# Constantes
MODEL_PATH = 'random_forest_model.pkl'
FEATURES_LIST = [
    'AddressOfEntryPoint', 'MajorLinkerVersion', 'MajorImageVersion', 
    'MajorOperatingSystemVersion', 'DllCharacteristics', 'SizeOfStackReserve', 'NumberOfSections'
]

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model():
    """Entraîner et sauvegarder un modèle RandomForestClassifier."""
    st.info("Entraînement du modèle, veuillez patienter...")

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

    # Sauvegarde du modèle
    joblib.dump(model, MODEL_PATH)

    # Affichage des métriques
    st.success(f"Précision du modèle : {accuracy:.3f}")
    st.success(f"Rappel du modèle : {recall:.3f}")

    # Graphique de matrice de confusion
    st.subheader("Matrice de confusion")
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.xlabel("Prédictions")
    plt.ylabel("Vérités terrain")
    st.pyplot(plt)

    return model, accuracy, recall

# Fonction pour charger ou entraîner le modèle
def load_or_train_model():
    """Charger le modèle si existant, sinon entraîner et sauvegarder."""
    if os.path.exists(MODEL_PATH):
        st.success("Modèle existant trouvé, chargement en cours...")
        model = joblib.load(MODEL_PATH)
        return model, None, None
    else:
        return train_and_save_model()

# Fonction pour traiter un fichier CSV ou Excel
def process_file(file, model):
    """Traiter un fichier .csv ou .xlsx et effectuer l'analyse."""
    try:
        # Lire le fichier en tant que dataframe pandas
        if file.name.endswith('.csv'):
            data = pd.read_csv(file)
        elif file.name.endswith('.xlsx'):
            data = pd.read_excel(file)

        st.success(f"Fichier {file.name} chargé avec succès !")
        st.write("**Aperçu des données :**")
        st.dataframe(data.head())

        # Vérifier si toutes les colonnes nécessaires sont présentes
        missing_features = [col for col in FEATURES_LIST if col not in data.columns]
        if missing_features:
            st.error(f"Colonnes manquantes : {missing_features}")
            return None

        # Prédictions sur les données
        predictions = model.predict(data[FEATURES_LIST])
        data['Prediction'] = predictions

        st.write("**Résultats des prédictions :**")
        st.dataframe(data[['Prediction']].value_counts().reset_index(name='Counts'))

        # Graphique des résultats de prédictions
        st.subheader("Distribution des Prédictions")
        plt.figure(figsize=(6, 4))
        sns.countplot(data['Prediction'], palette="Set2")
        plt.title("Distribution des prédictions (Malware vs Légitime)")
        plt.xlabel("Classe prédite")
        plt.ylabel("Nombre de cas")
        st.pyplot(plt)

        return data

    except Exception as e:
        st.error(f"Erreur lors du traitement du fichier : {str(e)}")
        return None

# Interface utilisateur Streamlit
def main():
    st.sidebar.header("🛡️ Détecteur de Malwares")
    st.sidebar.write("Téléchargez un fichier CSV ou Excel pour analyser les données ou effectuer des prédictions.")

    # Charger ou entraîner le modèle
    model, accuracy, recall = load_or_train_model()

    # Téléchargement de fichier CSV ou Excel
    uploaded_file = st.file_uploader("Téléchargez un fichier CSV ou Excel", type=["csv", "xlsx"])

    if uploaded_file is not None:
        # Affichage de l'état d'analyse
        st.info("Analyse en cours...")

        # Effectuer l'analyse du fichier téléchargé
        processed_data = process_file(uploaded_file, model)

        # Après l'analyse, permettre un nouveau téléchargement de fichier
        if processed_data is not None:
            st.success("Analyse terminée avec succès !")

if __name__ == "__main__":
    main()

