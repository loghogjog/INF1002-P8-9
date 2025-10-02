#Libraries for Keyword Detection
import re
from collections import Counter
from email import message_from_bytes
class Detection:

    risk = 0

    def keyword_detection(email_text):
        '''
        Goes through the email and checks how many suspicious characters
        are in that email, returns a risk score
        expects a text that has went through text_formatter
        '''
        keywords = Detection.load_keywords()
        tokens = Detection.text_formatter(email_text)
        counts = Counter()
        flagged_tokens = []

        # use i for weightage
        for index, token in enumerate(tokens):
            if token in keywords:
                counts[token] += 1
                flagged_tokens.append(token)
                risk += index
            
        max_phrase_len = 5
        sentence = len(tokens)
        for L in range(2, max_phrase_len + 1):
            for i in range(sentence - L + 1):
                phrase = ' '.join(tokens[i:i+L])
                if phrase in keywords:
                    counts[phrase] += 1
                    flagged_tokens.append(phrase)

        return counts, flagged_tokens


    def text_formatter(text):
        '''
        lowers text, removes punctuation, split on whitespace, removes zero-width and weird unicode if desired
        returns a list of single words
        '''
        text = text.lower()
        #removes zero-width space, zero-width joiner, zero-width no-break space
        text = re.sub(r'[\u200B-\u200D\uFEFF]','',text)
        #captures words,emails and domain-like tokens
        return re.findall(r'\b[\w@.-]+\b', text)

    def load_keywords():
        '''
        loads keywords.txt into a list
        Do variable = Detection.load_keywords()
        go to keywords.txt to modify/update keywords
        '''
        with open("keywords.txt", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    def risk_score():
        '''
        Returns a percentage of the score from keyword detection
        weightage??
        '''
        total_risk = (Detection.risk / 100) * 40 
        return total_risk



