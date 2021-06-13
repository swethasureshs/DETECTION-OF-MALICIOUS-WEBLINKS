import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
import pickle

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

random.seed(100)
# #### splitting the data into train data and test data

data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20)
print(len(data_train),len(data_test),len(labels_train),len(labels_test))
print(labels_train.value_counts())
print(labels_test.value_counts())


# ## Random Forest

RFmodel = RandomForestClassifier(n_estimators=100,random_state=5)
RFmodel.fit(data_train,labels_train)
rf_pred_label = RFmodel.predict(data_test)
print(list(labels_test)),print(list(rf_pred_label))


cm2 = confusion_matrix(labels_test,rf_pred_label)
print(cm2)
print("Accuracy:")
print(accuracy_score(labels_test,rf_pred_label))
result1 = classification_report(labels_test,rf_pred_label)
print("Classification Report:",)
print(result1)
# Saving the model to a file

file_name = "C:\\Users\\Swetha\\Downloads\\RandomForestModel.sav"
pickle.dump(RFmodel,open(file_name,'wb'))