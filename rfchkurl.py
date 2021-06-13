import joblib
import trial6fe

def pred(url):
#load the pickle file
 classifier = joblib.load("C:\\Users\\Swetha\\Downloads\\RandomForestModel1.sav")

 #checking and predicting
 checkprediction = trial6fe.main(url)
 prediction = classifier.predict(checkprediction)
 print(prediction)
 if(prediction==0):
    a = "SAFE URL"
    return a
 else:
    b = "MALICIOUS URL"
    return b


