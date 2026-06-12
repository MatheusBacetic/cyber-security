# Troubleshooting

## Problema 1 - Página incorreta do Nginx

### Sintoma

Ao acessar o endereço IP do servidor, a página exibida não era a página esperada.

### Investigação

Verificação da configuração do Nginx:

nginx -T

Consulta do diretório root configurado.

### Causa

O conteúdo esperado não estava localizado no diretório configurado pelo Nginx.

### Solução

Atualização do conteúdo em:

/var/www/html

e reinicialização do serviço.

---

## Problema 2 - Acesso SSH Negado

### Sintoma

A conexão SSH era estabelecida, porém a autenticação falhava.

### Investigação

Verificação do arquivo:

/etc/ssh/sshd_config

Análise dos parâmetros:

PermitRootLogin
PasswordAuthentication

### Causa

Tentativa de autenticação utilizando o usuário root.

### Solução

Utilização de um usuário comum para acesso SSH e administração via sudo.

---

## Problema 3 - Porta SSH Personalizada

### Sintoma

A conexão SSH não funcionava utilizando a porta padrão.

### Investigação

Verificação das portas em escuta:

ss -tulnp

Verificação das regras do firewall.

### Causa

O serviço SSH estava configurado para utilizar a porta 2409.

### Solução

Atualização dos comandos SSH e SCP para utilização da porta correta.

Exemplo:

ssh usuario@ip -p 2409

scp -P 2409 arquivo usuario@ip:~

---

## Problema 4 - Arquivo Transferido Não Encontrado

### Sintoma

Após a transferência via SCP o arquivo não era localizado.

### Investigação

Verificação do destino configurado no comando SCP.

### Causa

O arquivo foi enviado para o diretório home do usuário e não para o diretório web do Nginx.

### Solução

Localização do arquivo em:

/home/math

e posterior cópia para:

/usr/share/nginx/html

---

## Problema 5 - Perda das Regras nftables Após Reinicialização

### Sintoma

Após reiniciar o sistema, as regras do firewall desapareceram.

### Investigação

Consulta ao ruleset:

nft list ruleset

### Causa

As regras estavam apenas carregadas em memória.

### Solução

Criação do arquivo:

/etc/nftables.conf

e habilitação do serviço:

systemctl enable nftables

---

## Problema 6 - Contadores Não Atualizavam

### Sintoma

Os contadores apresentavam valor zero.

### Investigação

Verificação das regras associadas aos serviços.

### Causa

Os testes não estavam atingindo as regras monitoradas.

### Solução

Realização de conexões HTTP e SSH para validar o funcionamento dos counters.

---

## Lições Aprendidas

* Validar o serviço antes do firewall.
* Testar localmente antes de testar remotamente.
* Utilizar logs e counters para confirmar hipóteses.
* Trabalhar com configuração persistente.
* Separar regras por responsabilidade utilizando chains auxiliares.
