#training svm
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC  # "Support Vector Classifier"

legitimate_urls = pd.read_csv("C:\\Users\\Swetha\\Downloads\\fe-safetotalnew.csv")
phishing_urls = pd.read_csv("C:\\Users\\Swetha\\Downloads\\fe-phishingtotalnew.csv")

print(len(legitimate_urls))
print(len(phishing_urls))

urls = legitimate_urls.append(phishing_urls)

urls.head(5)

print(len(urls))
print(urls.columns)


# shuffling the rows in the dataset so that when splitting the train and test set are equally distributed
urls = urls.sample(frac=1).reset_index(drop=True)


# #### Removing class variable from the dataset
urls_without_labels = urls.drop('Label',axis=1)
urls_without_labels.columns
labels = urls['Label']
#labels

data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20)
print(len(data_train),len(data_test),len(labels_train),len(labels_test))
print(labels_train.value_counts())
print(labels_test.value_counts())


clf = SVC(kernel='rbf')

# fitting x samples and y classes
clf.fit(data_train,labels_train)
op = clf.predict(data_test)
print(list(labels_test)),print(list(op))


cm2 = confusion_matrix(labels_test,op)
print(cm2)
print(accuracy_score(labels_test,op))
print(classification_report(labels_test,op))
fn = "C:\\Users\\Swetha\\Downloads\\svm.pkl"
# Saving the model as a pickle file
joblib.dump(clf, open(fn,'wb'))



