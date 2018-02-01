'''
FWAF - Machine Learning driven Web Application Firewall
Author: Faizan Ahmad
Performance improvements: Timo Mechsner
Website: http://fsecurify.com
'''

def display_scores(vectorizer, tfidf_result):
    # http://stackoverflow.com/questions/16078015/
    scores = zip(vectorizer.get_feature_names(),
                 np.asarray(tfidf_result.sum(axis=0)).ravel())
    sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
    for item in sorted_scores:
        print "{0:50} Score: {1}".format(item[0], item[1])

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import os
from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import LogisticRegressionCV
from sklearn.cross_validation import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import cross_val_score
from sklearn import metrics
# import urllib.parse
from urllib import quote

import matplotlib.pyplot as plt

def loadFile(name):
    directory = str(os.getcwd())
    filepath = os.path.join(directory, name)
    with open(filepath,'r') as f:
        data = f.readlines()
    data = list(set(data))
    result = []
    for d in data:
        # d = str(urllib.parse.unquote(d))   #converting url encoded data to simple string
        d = str(quote(d))   #converting url encoded data to simple string
        result.append(d)
    return result

badQueries = loadFile('badqueries.txt')
validQueries = loadFile('goodqueries.txt')

badQueries = list(set(badQueries))
validQueries = list(set(validQueries))
allQueries = badQueries + validQueries
yBad = [1 for i in range(0, len(badQueries))]  #labels, 1 for malicious and 0 for clean
yGood = [0 for i in range(0, len(validQueries))]
y = yBad + yGood
queries = allQueries

vectorizer = TfidfVectorizer(min_df = 0.0, analyzer="char", sublinear_tf=True, ngram_range=(1,3)) #converting data to vectors
X = vectorizer.fit_transform(queries)
display_scores(vectorizer, X)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) #splitting data

badCount = len(badQueries)
validCount = len(validQueries)

# lgs = LogisticRegression(class_weight={1: 2 * validCount / badCount, 0: 1.0}) # class_weight='balanced')
# lgs = LogisticRegression(penalty='l1')
rng = np.random.RandomState(42)
clf = IsolationForest(max_samples=100, random_state=rng, n_jobs=4, contamination=(badCount /validCount + badCount))
print('fitting')
# lgs.fit(X_train, y_train) #training our model
clf.fit(X_train) #training our model
print ('done')

y_pred_train = clf.predict(X_train)
y1 = np.array(y_pred_train)
y2 = np.array(y_train)
print(len(y_pred_train))
print(len(y_train))
print(np.sum(y1 == y2))

##############
# Evaluation #
##############

# predicted = lgs.predict(X_test)
print clf.predict(vectorizer.transform(['/<script>alert(123)</script>']))

# fpr, tpr, _ = metrics.roc_curve(y_test, (lgs.predict_proba(X_test)[:, 1]))
# auc = metrics.auc(fpr, tpr)

print("Bad samples: %d" % badCount)
print("Good samples: %d" % validCount)
print("Baseline Constant negative: %.6f" % (validCount / (validCount + badCount)))
print("------------")
# print("Accuracy: %f" % lgs.score(X_test, y_test))  #checking the accuracy
# accu_list = cross_val_score(clf, X_train, y_train, scoring='accuracy', cv=10, n_jobs=-1)
# print('10 fold cv is', accu_list.mean())

# print("Precision: %f" % metrics.precision_score(y_test, predicted))
# print("Recall: %f" % metrics.recall_score(y_test, predicted))
# print("F1-Score: %f" % metrics.f1_score(y_test, predicted))
# print("AUC: %f" % auc)
