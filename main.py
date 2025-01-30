
from random import randint
import random as rand
import os
import base64
import hashlib
import traceback
from typing import *


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
    teste = 0
    while(True):
        n = randint(2**1023,(2**1024)-1)
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
    #print("phi:", phi)
    #print("chave pública e:",e)
    #print("chave privada d:",d)
    return e,n,d


# publicKey(e),publicExp(n),privateKey(d) = makeKey(GeradorPrimos(),GeradorPrimos())

#função de encriptação. recebe um texto com hash OAEP, chave publica "e" e expoente publico "n"
def encriptar(mensagem, e, n):
    #transforma a mensagem codificada em um tipo que podemos operar
    msg = int.from_bytes(mensagem, 'big')
    #msg elevado a "e" no modulo "n"
    msgEncriptada = pow(msg,e,n)
    #retorna a mensagem com rsa e OAEP aplicados
    return(msgEncriptada)

#função de decriptaçao. recebe texto encriputado e com OAEP, chave privada "d" e expoente publico "n"
def decriptar(textoEncriptado, d, n):
    #texto elevado a "d" no modulo "n"
    msg = pow(textoEncriptado, d, n)
    #tamanho da mensagem
    tamanho = (n.bit_length() + 7) // 8
    #converte para bytes
    msgDecriptadaOAEP = msg.to_bytes(tamanho, 'big')
    #retorna a mensagem, com rsa decriptado mas ainda com OAEP
    return msgDecriptadaOAEP
    

def mask(seed, length, hash_func=hashlib.sha256):
    counter = 0
    output = b''
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        output += hash_func(seed + counter_bytes).digest()
        counter += 1
    return output[:length]

def encode(message, k, hash_func=hashlib.sha256):
    hashLen = hash_func().digest_size  # 32 bytes
    messageLen = len(message)
    label = b''

    if messageLen > k - 2 * hashLen - 2:
        raise ValueError("mensagem muito longa")
        return 1
    
    #gera string aleatoria
    seed = os.urandom(hashLen)
    #aplica função de rash e armazena o valor em bytes
    labelHash = hash_func(label).digest()

    #cria um bloco de dados do tamanho certo com label na frente
    ps = b'\x00' * (k - messageLen - 2 * hashLen - 2)
    db = labelHash + ps + b'\x01' + message.encode(encoding="utf-8")

    #aplica mascara ao data block
    dbMask = mask(seed, len(db), hash_func)
    maskeddb = bytes(a ^ b for a, b in zip(db, dbMask))

    #aplica mascara a seed
    seedMask = mask(maskeddb, hashLen, hash_func)
    maskedSeed = bytes(a^b for a,b in zip(seed,seedMask))

    return b'\x00' + maskedSeed + maskeddb

def decode(message,k, hash_func=hashlib.sha256):
    label = b''
    hashLen = hash_func().digest_size
    if len(message) != k:
        raise ValueError("tamanho incorreto")

    #separando componentes
    _, maskedSeed, maskeddb = message[0], message[1:hashLen+1], message[hashLen+1:]

    #recuperando seed
    seedMask = mask(maskeddb, hashLen, hash_func)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))


    #recuperando data block
    dbMask = mask(seed, len(maskeddb), hash_func)
    db = bytes(a ^ b for a, b in zip(maskeddb, dbMask))

    #extraindo mensagem
    tamanhoHash = hash_func(label).digest()
    if db[:hashLen] != tamanhoHash:
        raise ValueError("label hash incorreto")

    #encontrando \x01 e extraindo mensagem
    index = db.find(b'\x01', hashLen)
    if index == -1:
        raise ValueError("formato invalido")
    
    return db[index+1:]


def assinar_arquivo( file_name_ext:str, prk_file:str ) -> None:

    ''' 
        função pra assinar um arquivo, gerando um arquivo em base 64 da mensagem (bytes do arquivo),
        hash da mensagem e os outras informações para verificação.
        o arquivo resultante terá a extensão '.b64' e possuirá a seguinte estrutrura:
            - primeiros n (tamanho fixo) bytes -> hash criptografado do arquivo da mensagem
            - byte seguinte -> numero 'c' de caracteres de extensão do arquivo da mensagem
            - próximos c bytes - extensão do arquivo da mensagem
            - resto dos bytes - arquivo da mensagem
    '''

    # tenta ler arquivo da mensagem como bytes e arquivo da chave privada, retorna None em caso de erro
    try:
        with open(f'./.files/{file_name_ext}', 'rb') as f:
            msg_bytes = f.read()
        with open(f'./.prk/{prk_file}', 'r') as f:
            prk = f.read()
    except Exception as exc:
        print(f'\nERRO!!!: {exc}')
        print(f"TRACEBACK:\n{traceback.format_exc()}")
        return None

    # caso não dê erro na leitura dos bytes do arquivo:
    # calcula hash sha3-512 dos bytes do arquivo como um string
    hash_str = hashlib.sha3_512(msg_bytes).hexdigest()

    # codifica string do hash calculado para bytes em utf-8
    hash_bytes = hash_str.encode(encoding = "utf-8")

    # hash_bytes = encriptar_rsa(hash_bytes, prk, ...)

    # obtém nome e extensão do arquivo
    file_name, file_extension = os.path.splitext(file_name_ext)
    num_char_file_ext = len(file_extension) - 1 # ignora o '.'

    # constroi sequencia de bytes do arquivo final (assinado)
    msg_signed = hash_bytes + num_char_file_ext.to_bytes(1, "big") + file_extension[1:].encode(encoding = "utf-8") + msg_bytes

    # converte para base64
    msg_signed_b64 = base64.b64encode(msg_signed)

    # tenta salvar
    try:
        with open(f".b64/{file_name}_signed.b64", "wb") as f:
            f.write(msg_signed_b64)
        print(f"\narquivo assinado e convertido para base 64 gerado e salvo em '.b64/{file_name}_signed.b64'\n")
    except Exception as exc:
        print(f"\nERRO!!!: {exc}")
        print(f"NÃO FOI POSSÍVEL SALVAR ARQUIVO '.b64/{file_name}_signed.b64'")
        print(f"TRACEBACK:\n{traceback.format_exc()}")


'''
    função para verificar a assinatura, decodificando o arquivo b64 gerado na função anterior, a partir
    dos mesmos critérios.
    reconstrói o arquivo da mensagem original
'''
def verificar_assinatura( b64_file_name:str, puk_file:str ) -> None:

    # tenta ler arquivo b64 como string e arquivo da chave publica, retorna None em caso de erro
    try:
        with open(f"./.b64/{b64_file_name}", "r") as f:
            b64_file = f.read()
        with open(f"./.puk/{puk_file}") as f:
            puk = f.read()
    except Exception as exc:
        print(f"\nERRO!!!: {exc}")
        print(f"NÃO FOI POSSÍVEL LER ARQUIVOS './.b64/{b64_file_name}' e './.puk/{puk_file}'")
        print(f"TRACEBACK:\n{traceback.format_exc()}")
        return
    
    len_hash = 128  # quantidade fixa de caracteres do hash (deve ser do criptografado, 128 é do hash em claro)
    signed_msg_bytes = base64.b64decode(b64_file)   # decodificação base 64
    hash_received = signed_msg_bytes[:len_hash].decode(encoding="utf-8")    # hash "recebido" no arquivo de assinatura b64
    # hash_received = decriptar(hash_received, puk, ...)
    num_char_file_ext = signed_msg_bytes[len_hash]
    file_extension = signed_msg_bytes[len_hash+1:len_hash+1+num_char_file_ext].decode(encoding="utf-8")
    msg_received_bytes = signed_msg_bytes[len_hash+1+num_char_file_ext:] # bytes da mensagem original
    file_name = b64_file_name[:-11] # ignora o '_signed.b64'

    # calcula hash da mensagem recebida
    hash_calculated = hashlib.sha3_512(msg_received_bytes).hexdigest()

    validated = True

    if hash_calculated == hash_received:
        print("\nassinatura válida !!! aeee :) ")
    else:
        print("\nassinatura invalidada !!!  :( ")
        validated = False

    print('\nRestaurando arquivo...')

    try:
        with open(f"./.checked_files/{file_name}_{puk_file[:-4]}_{'validated' if validated else 'invalidated'}.{file_extension}", "wb") as f:
            f.write(msg_received_bytes)
    except Exception as exc:
            print(f"\nERRO!!!: {exc}")
            print("NÃO FOI POSSÍVEL RESTAURAR ARQUIVO VERIFICADO")
            print(f"TRACEBACK:\n{traceback.format_exc()}")
            return
    
    print(f"\narquivo verificado está restaurado em checked_files/{file_name}.{file_extension}")


'''
    função para printar as opções do programa para o usuário, e reagir de acordo
'''
def opcoes_iniciais() -> Optional[int] :
    print("\nEscolha uma opção:")
    print("1 - Gerar chaves")
    print("2 - Assinar arquivo")
    print("3 - Verificar assinatura")
    print("\nDigite 's' para sair.")
    op = input("\n> ")
    if not op.isalnum() or not op in ("1","2","3","s","S"):
        print("Opção inválida\n\n")
        return 
    return op

def salvar_chaves() -> None:
    '''
        função para salvar a chave publica na pasta .pub e a chave privada na pasta .prv
    '''
    while True:
        print('\nEscolha um nome para o arquivos das chaves pública e privada.')
        print('Obs: O nome deve conter apenas caracteres alfabéticos e ter no mínimo 2 e no máximo 255 caracteres.\n')
        print("Digite 'v' para voltar.")
        entrada = input('>')

        if entrada.lower() == 'v': return
        if not entrada.isalpha or not 2<len(entrada)<256:
            print('O nome deve conter apenas caracteres alfabéticos e ter no mínimo 2 e no máximo 255 caracteres.\n')
        else:
            name = entrada
            print('Gerando chaves...')
            puk, n, prk = makeKey(GeradorPrimos(), GeradorPrimos())

            try:
                with open(f'./puk/{name}.puk', 'w') as f:
                    f.write(hex(puk)[2:])
                    f.write(hex(n)[2:])
            except Exception as exc:
                print(f"\nERRO!!!: {exc}")
                print("NÃO FOI POSSÍVEL SALVAR CHAVES")
                print(f"TRACEBACK:\n{traceback.format_exc()}")
                return



'''
    função para mostrar as opções de chaves privadas disponíveis para assinatura na pasta ./.prk, e
    retornar o nome do arquivo da chave privada escolhida para a função principal
'''
def opcoes_chaves_privadas() -> Optional[str] :
    while True:
        prks = os.listdir("./.prk")
        print("\nEscolha umas das chaves privadas em ./.prk:")
        for idx_prk in range(len(prks)):
            print(f"{idx_prk+1} - {prks[idx_prk]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(prks)+1))]:
            print("\nOpção inválida")
        else:
            prk_file = prks[int(op)-1]
            return prk_file


'''
    função para mostrar as opções de chaves publicas disponíveis para assinatura na pasta ./.puk, e
    retornar o nome do arquivo da chave publica escolhida para a função principal
'''
def opcoes_chaves_publicas() -> Optional[str] :
    while True:
        puks = os.listdir("./.puk")
        print("\nEscolha umas das chaves publicas em ./.puk:")
        for idx_puk in range(len(puks)):
            print(f"{idx_puk+1} - {puks[idx_puk]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(puks)+1))]:
            print("\nOpção inválida")
        else:
            puk_file = puks[int(op)-1]
            return puk_file


'''
    função para mostrar as opções de arquivos disponíveis para assinatura na pasta './.files' ou
    para verificação na pasta './.b64', e retornar o nome do arquivo escolhido para a função principal
'''
def opcoes_arquivos( folder:str ) -> Optional[str]:
    while True:
        files = os.listdir(folder)
        print(f"\nEscolha um dos arquivos em '{folder}':")
        for idx_file in range(len(files)):
            print(f"{idx_file+1} - {files[idx_file]}")
        print("\nDigite 'v' para voltar")
        op = input("\n> ")
        if op.lower() == 'v': return
        if not op.isalnum or op not in [str(x) for x in list(range(1,len(files)+1))]:
            print("\nOpção inválida")
        else:
            file_name = files[int(op)-1]
            return file_name

#GeradorPrimos() gera um número primo de 1024 bits
#makeKey() recebe dois primos e retorna e,n,d
#encode aplica codigicação OAEP
#decode remove OAEP
#encriptar recebe mensagem com OAEP, e, n. retorna mensagem encriptada por rsa
#decriptar recebe mensagem encriptada e com OAEP, e, d. retorna mensagem apenas com OAEP aplicado
def main():    
    #exemplo do funcionamento
    #e,n,d = makeKey(GeradorPrimos(),GeradorPrimos())
    #message = "teste"    
    #encoded_msg = encode(message, (e.bit_length() + 7) // 8)
    #encriptada = encriptar(encoded_msg,e,n)
    #decriptada = decriptar(encriptada,d,n)
    #decoded_msg = decode(decriptada, (e.bit_length() + 7) // 8)
    #print(decoded_msg)


    while True:
        op = opcoes_iniciais()
        if op.lower()=='s': return(print("\nEncerrando...\n"))

        if op == "1":
            name_file = salvar_chaves()
        elif op == "2":
            prk = opcoes_chaves_privadas()
            if prk:
                file_name = opcoes_arquivos('./.files')
                if file_name: assinar_arquivo(file_name, prk)
        elif op=="3":
            puk = opcoes_chaves_publicas()
            if puk:
                file_name = opcoes_arquivos('./.b64')
                if file_name: verificar_assinatura(file_name, puk)
            
    


if __name__ == "__main__":
    main()

