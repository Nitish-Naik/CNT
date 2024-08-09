# Function to convert the string to lowercase

def toLowerCase(text):
    return text.lower()


# Function to remove all spaces in a string

def removeSpaces(text):
    newText = ''

    for i in text:
        if i == " ":
            continue
        else:
            newText = newText + i
    return newText

# Function to group 2 elements of a string
# as a list element


def Diagraph(text):
    Diagraph = []
    group = 0
    for i in range(2, len(text), 2):
        Diagraph.append(text[group: i])

        group = i
    Diagraph.append(text[group : ])
    return Diagraph


text_Plain = 'instruments'
print(Diagraph(removeSpaces(toLowerCase(text_Plain))))






# Function to fill a letter in a string element
# If 2 letters in the same string matches


def FillerLetter(text):
    k = len(text)
    if k % 2 == 0:
        for i in range(0, k, 2):
            