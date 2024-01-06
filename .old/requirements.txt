#!/bin/bash

# Install required Python packages
pip3 install rake-nltk
pip3 install summa
pip3 install nltk
pip3 install gensim
pip3 install pandas
pip3 install Counter
pip3 install keywords
pip3 install BeautifulSoup4
pip3 install lxml
pip3 install pandas
pip3 install joblib
pip3 install scikit-learn

# Make it executable by running the following command in the terminal: `chmod +x requirements.sh`
# To run the script: `./requirements.sh`
: '
Steps:
 1.⁠ ⁠Run preprocessing.ipynb⁠ in the directory ⁠ NLP ⁠
 2.⁠ ⁠Run mitre-framework-scraped.py
 3.⁠ ⁠Run supervised_test_server.py⁠
 4.⁠ ⁠Run ⁠predict.py
'
