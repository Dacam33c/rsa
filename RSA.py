from random import randint
import random as rand

def binToString(bin0,size):
    string = str(bin0)[2:]
    while(len(string) < size):
        string = "0" + string
    return string



def MillerRabin(n, iteracoes):
    #n = numero testado
    #iteracoes aumenta a confiabilidade do teste
    
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(iteracoes):
        a = rand.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def GeradorPrimos():
    teste = 0;
    while(True):
        n = randint(2**1024,(2**1025)-1)
        teste +=1
        print(teste)
        if(MillerRabin(n,10)):
            print(n)
            return True

#N1 deve ser maior que N2
def euclides(n1,n2):
    while(n2 != 0):
        n1, n2 = n2, n1 % n2
    return n1 == 1
    
def makeKey(primo1,primo2):
    if (primo1 == primo2):
        print("primos aleatórios iguais")
        return 0
    
    n = primo1 * primo2
    phi = (primo1 - 1) * (primo2 - 1)
    
    e = randint(1,n)
    
    if (phi % e == 0):
         print("Φ = e")
         return 0
        
    #CHAMAR FUNÇÃO DE EUCLIDES COM N1>N2!!!!!!!!!