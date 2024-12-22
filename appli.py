import streamlit as st
import pandas as pd
import joblib
import os
import pefile
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import hashlib

# Chemin vers le modèle sauvegardé
MODEL_PATH = 'random_forest_model.pkl'

# Fonction pour charger le modèle
@st.cache_resource
def load_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    else:
        st.error("Le modèle n'est pas disponible. Veuillez entraîner le modèle et réessayer.")
        return None

# Fonction pour extraire les attributs d'un fichier PE (exécutable)
def extract_pe_attributes(file_path):
    try:
        pe = pefile.PE(file_path)
        return {
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections
        }
    except Exception as e:
        st.error(f"Erreur lors de l'extraction des attributs : {e}")
        return None

# Fonction pour extraire les caractéristiques d'une ligne d'un fichier Excel
def extract_features_from_row(row):
    try:
        return {
            'AddressOfEntryPoint': row['AddressOfEntryPoint'],
            'MajorLinkerVersion': row['MajorLinkerVersion'],
            'MajorImageVersion': row['MajorImageVersion'],
            'MajorOperatingSystemVersion': row['MajorOperatingSystemVersion'],
            'DllCharacteristics': row['DllCharacteristics'],
            'SizeOfStackReserve': row['SizeOfStackReserve'],
            'NumberOfSections': row['NumberOfSections']
        }
    except KeyError as e:
        st.error(f"Colonne manquante dans les données : {e}")
        return None

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model(data):
    # Séparer les caractéristiques (X) et les étiquettes (y)
    X = data.drop("legitimate", axis=1)  # Caractéristiques
    y = data["legitimate"]  # Étiquettes

    # Diviser les données en ensembles d'entraînement et de test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Créer et entraîner le modèle
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Sauvegarder le modèle avec joblib
    joblib.dump(model, MODEL_PATH)
    st.success(f"Le modèle a été sauvegardé dans le fichier {MODEL_PATH}")

    # Évaluer le modèle
    y_pred = model.predict(X_test)
    st.write("Évaluation du modèle :")
    st.text(classification_report(y_test, y_pred))

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

        st.download_button("Télécharger le rapport", result, file_name="rapport_analyse.txt")

        # Suppression du fichier temporaire
        os.remove(temp_file)

        return result
    except Exception as e:
        return f"Erreur d'analyse : {str(e)}"


def main():
    # Chargement du modèle
    model = load_model()

    # Interface utilisateur Streamlit
    st.title("🛡️ Détecteur de Malwares")
    st.write("Analysez des fichiers exécutables ou des fichiers Excel contenant des informations sur les exécutables.")
    
    # Choisir d'entraîner le modèle ou de faire une prédiction
    action = st.selectbox("Que souhaitez-vous faire ?", ("Analyser un fichier", "Entraîner un modèle"))

    if action == "Entraîner un modèle":
        # Charger les données pour entraîner le modèle
        uploaded_file = st.file_uploader("Télécharger un fichier Excel (CSV, XLSX, XLS)", type=["csv", "xlsx", "xls"])
        if uploaded_file is not None:
            try:
                # Lire le fichier
                if uploaded_file.name.endswith(".csv"):
                    data = pd.read_csv(uploaded_file)
                else:
                    data = pd.read_excel(uploaded_file)

                # Vérifier les colonnes nécessaires
                required_columns = ['AddressOfEntryPoint', 'MajorLinkerVersion', 'MajorImageVersion', 
                                    'MajorOperatingSystemVersion', 'DllCharacteristics', 
                                    'SizeOfStackReserve', 'NumberOfSections', 'legitimate']
                missing_columns = [col for col in required_columns if col not in data.columns]
                if missing_columns:
                    st.error(f"Colonnes manquantes : {', '.join(missing_columns)}")
                else:
                    st.write("Données chargées :")
                    st.dataframe(data.head())

                    # Entraîner et sauvegarder le modèle
                    train_and_save_model(data)

            except Exception as e:
                st.error(f"Erreur lors du traitement du fichier : {e}")

    elif action == "Analyser un fichier":
        # Choix du type de fichier
        file_type = st.radio("Choisissez le type de fichier à analyser :", ("Exécutable", "Excel"))

        if file_type == "Exécutable":
            uploaded_file = st.file_uploader("Télécharger un fichier exécutable (.exe, .dll, .sys)", type=["exe", "dll", "sys"])
            if uploaded_file is not None:
                result = predict_malware(uploaded_file, model)
                st.write(result)

        elif file_type == "Excel":
            uploaded_file = st.file_uploader("Télécharger un fichier Excel (CSV, XLSX, XLS)", type=["csv", "xlsx", "xls"])
            if uploaded_file is not None:
                try:
                    # Lire le fichier
                    if uploaded_file.name.endswith(".csv"):
                        data = pd.read_csv(uploaded_file)
                    else:
                        data = pd.read_excel(uploaded_file)

                    st.write("Données chargées :")
                    st.dataframe(data.head())

                    # Extraire les caractéristiques et prédire
                    features = data.apply(extract_features_from_row, axis=1).dropna()
                    features_df = pd.DataFrame(features.tolist())
                    if model is not None:
                        predictions = model.predict(features_df)
                        probabilities = model.predict_proba(features_df)

                        # Ajout des résultats au DataFrame original
                        data['Prediction'] = predictions
                        data['Probabilité Malware'] = probabilities[:, 1]
                        data['Probabilité Légitime'] = probabilities[:, 0]

                        st.write("Résultats des prédictions :")
                        st.dataframe(data)

                        # Téléchargement des résultats
                        result_file = 'resultats_predictions.xlsx'
                        data.to_excel(result_file, index=False)
                        with open(result_file, "rb") as file:
                            st.download_button(
                                label="Télécharger les résultats",
                                data=file,
                                file_name=result_file,
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                    else:
                        st.error("Le modèle n'est pas chargé.")
                except Exception as e:
                    st.error(f"Erreur lors du traitement du fichier : {e}")

if __name__ == "__main__":
    main()
