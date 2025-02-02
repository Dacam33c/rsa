# rsa

João Pedro Carvalho de Oliveira Rodrigues 221017032
Gabriel Maurício Chagas 221017097
Segurança computacional noturno

Como usar:
O programa em python relaiza a geração de chaves privada e pública aleatórias, codificação e decodificação OAEP, encriptação e decriptação RSA, com o propósito de assinar digitalmente e virificar a assinatura de artquivos.
Ao executar main.py são apresentadas 3 opções. A primeira é a geração de chaves, que é salva em um arquivo. A segunda é a realização da assinatura a partir de uma chave criada pela opção anterior, que salva um arquivo assidano com a chave selecionada. Por fim é possível verificar a assinatura de um arquivo salvo junto com uma das chaves criadas, que informa se ela é válida ou não. As chaves ficam salvas nas pastas .prk e .puk, enquanto os arquivos a serem assinas estão em .files, são salvos em .b64 quando assinados e caso a validação seja bem sucedida vão para .checked_files.
