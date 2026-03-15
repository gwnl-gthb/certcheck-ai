# CertCheck AI 🛡️🤖

**CertCheck AI** est un analyseur de conformité pour certificats X.509 (eIDAS, PSD2, CAB Forum) propulsé par l'IA. Il permet de comparer techniquement un certificat binaire avec sa Politique de Certification (PC) au format PDF.

## ✨ Fonctionnalités
- **Analyseur ASN.1 intelligent** : Décodage complet des extensions critiques (SAN, AIA, QCStatements, PSD2, CABF).
- **Rendu Hiérarchique** : Visualisation claire et repliable de la structure du certificat.
- **Audit Assisté par IA** : Utilise Claude 3.5 Sonnet pour valider les champs par rapport aux règles métier extraites d'un PDF.

## 🚀 Installation
1. Clonez le dépôt : `git clone https://github.com/gwnl-gthb/certcheck-ai.git`
2. Ouvrez `index.html` dans un navigateur moderne.
3. *Note : Pour l'appel API Anthropic, utilisez une extension de navigateur "Allow CORS" ou hébergez le fichier sur un serveur local.*

## 🛠️ Utilisation
1. Chargez votre certificat `.pem` ou `.crt`.
2. Chargez le PDF de la Politique de Certification (PC).
3. Sélectionnez les pages contenant les profils (ex: section 7.1).
4. Saisissez votre clé API Anthropic et lancez l'analyse.

## ⚖️ Licence
Distribué sous licence MIT. Voir `LICENSE` pour plus d'informations.
