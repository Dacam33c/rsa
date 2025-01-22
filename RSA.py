
from random import randint
import random as rand

import os
import base64
import hashlib
import traceback

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
        if(MillerRabin(n,10)):
            return n

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
    e = randint(1,phi)
    #CHAMAR FUNÇÃO DE EUCLIDES COM N1>N2!!!!!!!!!
    while (not euclides(phi,e)):
        e = randint(1,phi)
        
    #d é o inverso multiplicativo mod phi de e
    #significa que, ao multiplicar d * e e entao tirar mod phi o resultado será 1
    
    d = pow(e, -1, phi)
    print("phi:", phi)
    print("chave pública e:",e)
    print("chave privada d:",d)
    return e,d


# publicKey,privateKey = makeKey(GeradorPrimos(),GeradorPrimos())


''' 
    função pra assinar um arquivo, gerando um arquivo em base 64 da mensagem (bytes do arquivo) e
    hash da mensagem.
    os primeiros bytes do arquivo são o hash criptografado gerado a partir da mensagem cri (tamanho fixo).
    os restos dos bytes são do arquivo da msg original
'''
def assinar_arquivo( file_name_ext:str ):

    # tenta ler arquivo da mensagem como bytes, retorna None em caso de erro
    try:
        with open(file_name_ext, 'rb') as f:
            msg_bytes = f.read()
    except Exception as exc:
        print(f'\nERRO!!!:\n{exc}\n')
        print(traceback.format_exc())
        return None

    # caso não dê erro na leitura dos bytes do arquivo:
    # calcula hash sha3-512 dos bytes do arquivo como um string
    hash_str = hashlib.sha3_512(msg_bytes).hexdigest()

    # codifica string do hash calculado para bytes utf-8
    hash_bytes = hash_str.encode(encoding = "utf-8")

    # hash_bytes = encriptar_rsa(hash_bytes, key, ...)

    # obtém nome e extensão do arquivo
    file_name, _ = os.path.splitext(file_name_ext)

    # constroi sequencia de bytes do arquivo final (assinado)
    msg_signed = hash_bytes + msg_bytes

    # converte para base64
    msg_signed_b64 = base64.b64encode(msg_signed)

    # tenta salvar
    try:
        with open(f'./{file_name}_signed.b64', 'wb') as f:
            f.write(msg_signed_b64)
        print(f'\narquivo assinado em b64 gerado e salvo como "./{file_name}_signed.b64"\n')
    except Exception as exc:
        print(f"\nERRO!!!:\n{exc}\n")
        print(traceback.format_exc())


'''
    função para verificar a assinatura, decodificando o arquivo b64 gerado na função anterior, a partir
    dos mesmos critérios
'''
def verificar_assinatura( b64_file_name:str ):
    # tenta ler arquivo .b64 como string. retorna None em caso de erro
    try:
        with open(b64_file_name, 'r') as f:
            b64_file = f.read()
    except Exception as exc:
        print(f'\nERRO!!!:\n{exc}\n')
        print(traceback.format_exc())
        return None
    
    len_hash = 128  # quantidade fixa de caracteres do hash (deve ser do criptografado, 128 é do hash em claro)
    signed_msg_bytes = base64.b64decode(b64_file)   # decodificação base 64
    hash_received = signed_msg_bytes[:len_hash].decode(encoding="utf-8")    # hash "recebido" no arquivo de assinatura (.b64)
    # hash_received = decriptar(hash_received, key, ...)
    msg_received_bytes = signed_msg_bytes[len_hash:]

    hash_calculated = hashlib.sha3_512(msg_received_bytes).hexdigest()

    if hash_calculated == hash_received:
        print("assinatura validada !!! aeee :) ")
    else:
        print("assinatura invalidada !!!  :(")




