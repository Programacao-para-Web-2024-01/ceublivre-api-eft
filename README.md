# CeubLivre-API

## Autenticação

Este microsserviço gerencia o processo de autenticação e autorização dos usuários para acessar o marketplace.

### Autenticar usuários (2 pontos)

O microsserviço deve garantir que apenas usuários autenticados possam acessar
recursos e serviços da aplicação.

### Gerenciamento de sessão (1 ponto)

Capacidade de gerenciar sessões de usuário e garantir que um usuário
autenticado permaneça autenticado até que saia ou expire a sessão.

### Registro de usuário (2 pontos)

Capacidade de criar uma nova conta para o usuário realizando todos os
procedimentos de criptografia e segurança.

### Esqueci a senha (1 ponto)

Realizar o envio de email para que o usuário seja capaz de resetar sua senha.

### Personalização de login (1 ponto)

Capacidade de permitir que o usuário personalize seu login, como alterar sua
senha, nome de usuário, entre outros.

### Suporte a múltiplos fatores de autenticação (3 pontos)

Capacidade de suportar vários fatores de autenticação,
como senhas, tokens de autenticação, entre outros, para aumentar a segurança do login.

### Integração com provedores de identidade externos (3 pontos para cada provedor)

Capacidade de integrar-se com provedores de
identidade externos, como o Google, Facebook, entre outros, para fornecer uma experiência de login mais rápida e
conveniente para o usuário.

### Auditoria e relatórios (1 ponto)

Capacidade de fornecer auditoria e relatórios para registrar e rastrear
atividades de login e autenticação, como tentativas de login inválidas, alterações de senha, entre outros.

**Total: ao menos 14 pontos**

---

## Catálogo de produtos

Este microsserviço gerencia a lista de produtos disponíveis no marketplace.

### Criação de produtos (2 pontos)

Capacidade de permitir que os vendedores do marketplace criem novos produtos, adicionando informações como nome,
descrição, imagens, preço, categoria, entre outros.

### Atualização de produtos (2 pontos)

Capacidade de permitir que os vendedores do marketplace atualizem as informações de produtos existentes, como imagens,
preço, descrição, categoria, entre outros.

### Exclusão de produtos (1 ponto)

Capacidade de permitir que os vendedores do marketplace excluam produtos que não estejam mais disponíveis ou que não
estejam mais em estoque.

### Gerenciamento de categorias de produtos (2 pontos)

Capacidade de permitir que os administradores do marketplace cadastrem, atualizem e excluam possíveis categorias de
produtos.

### Listar todos os produtos (1 ponto)

Capacidade de listar todos os produtos cadastrados no marketplace.

### Gerenciamento de variações (1 ponto para cada variação)

Permitir que os vendedores possam criar e gerenciar variações de produtos, como tamanhos, cores, modelos, etc.

### Controle de versão de produtos (3 pontos)

Permitir que os vendedores possam gerenciar diferentes versões de um mesmo produto, como por exemplo, uma nova versão
com um preço atualizado ou uma descrição mais detalhada.

**Total: Pelo menos 11 pontos**

---

## Carrinho de compras

Este microsserviço gerencia as operações do carrinho de compras do usuário.

### Adicionar produtos ao carrinho (2 pontos)

Capacidade de permitir que os usuários adicionem produtos ao seu carrinho de compras.

### Remover produtos do carrinho (2 pontos)

Capacidade de permitir que os usuários removam produtos do seu carrinho de compras.

### Alterar quantidade de produtos no carrinho (1 ponto)

Capacidade de permitir que os usuários alterem a quantidade de produtos no seu carrinho de compras.

### Cálculo do total do carrinho (1 ponto)

Capacidade de calcular o valor total dos produtos no carrinho do usuário.

### Verificação de disponibilidade de produtos (2 pontos)

Capacidade de verificar se os produtos adicionados ao carrinho ainda estão disponíveis no estoque.

### Gerenciamento do carrinho (2 pontos)

Capacidade de criar um novo carrinho e possuir apenas um como ativo.

**Total: 10 pontos**

---

## Pagamentos
Este microsserviço gerencia o processo de pagamento para os produtos comprados no marketplace.

### Registro de histórico de transações (1 ponto)

Capacidade de registrar o histórico de transações, incluindo informações como o valor da transação, o método de
pagamento, entre outros.

### Integração com PIX (5 pontos)

Capacidade de gerar um QR Code para efetuar o pagamento da transação e atualizar a transação.

### Integração com provedores de cartão de créditos (4 pontos para cada)

Capacidade de integração com provedores de cartão de créditos e pagamento (Ex: Google Pay, Apple Pay, PayPal, Stripe,
etc)

**Total: ao menos 10 pontos**

---

## Gerenciamento de pedidos

Este microsserviço gerencia o processo de criação, atualização e entrega de pedidos, armazenando as informações dos
pedidos.

### Criação de pedido (2 pontos)

Capacidade de criar um pedido com as informações de entrega do cliente, produtos a serem entregues, valor do pedido e
valor do frete.

### Atualização do pedido (1 ponto)

Capacidade de atualizar um pedido com as informações de entrega.

### Relatórios de pedidos (3 pontos)

Manter um registro detalhado de todos os pedidos realizados, incluindo informações como produtos adquiridos, informações
de entrega, valor total do pedido, entre outros. Permitir que os administradores gerem relatórios com base nessas
informações.

### Controle de estoque (1 ponto)

Atualizar o estoque de produtos com base nos pedidos processados, garantindo que os produtos estejam disponíveis para
entrega.

### Notificações (4 pontos)

Enviar notificações por e-mail ou por meio de aplicativos para manter os usuários atualizados sobre o status de seus
pedidos, incluindo confirmação de pedidos, informações de rastreamento de entrega e atualizações de status.

### Gerenciamento de devoluções (3 pontos)

Gerenciar solicitações de devolução, permitindo que os usuários solicitem devoluções e acompanhando todo o processo de
devolução do produto.

**Total: 13 pontos**

---

## Interações

Este microsserviço gerencia as avaliações e comentários deixados pelos usuários sobre os produtos comprados, assim como
perguntas e repostas.

### Gerenciamento de avaliações (2 pontos)

Permitir que os usuários possam avaliar os produtos comprados e deixar uma nota ou estrela e um comentário sobre sua
experiência.

* Permitir avaliações com foto (1 ponto)

### Gerenciamento de comentários (2 pontos)

Permitir que os usuários possam comentar nas avaliações de outros usuários.

### Gerenciamento de perguntas (1 ponto)

Permitir que os usuários possam fazer perguntas sobre os produtos para os vendedores.

### Gerenciamento de respostas (1 ponto)

Permitir que os vendedores possam responder às perguntas dos usuários.

### Controle de conteúdo (3 pontos)

Garantir que o conteúdo gerado pelos usuários esteja em conformidade com as regras de uso do marketplace, como evitar
conteúdo ofensivo, racista ou spam.

### Moderação de conteúdo (2 pontos)

Fornecer ferramentas para que os moderadores possam revisar e remover conteúdo inadequado.

**Total: 12 pontos**

---

## Controle de estoque

Este microsserviço gerencia o controle de estoque dos produtos disponíveis no marketplace, permitindo que os vendedores
atualizem suas quantidades de estoque e alertando os usuários quando um produto está fora de estoque

### Atualização de estoque (2 pontos)

Manter o controle dos níveis de estoque de cada produto e atualizá-los à medida que as vendas são realizadas ou quando
novos produtos são adicionados.

### Notificação de estoque baixo (4 pontos)

Notificar os vendedores do marketplace quando um produto estiver com baixo estoque, permitindo que eles reabasteçam os
produtos rapidamente.

### Alertas de estoque esgotado (4 pontos)

Notificar os usuários quando um produto estiver fora de estoque, permitindo que eles decidam se desejam ser notificados
quando o produto estiver novamente disponível.

### Análise de estoque (3 pontos)

Fornecer análises de estoque, como os produtos mais vendidos, os produtos com baixo estoque, entre outros, para ajudar
os vendedores e administradores do marketplace a tomar decisões informadas sobre o estoque.

**Total: 13 pontos**

---

## Gerenciamento de usuários

Este microsserviço gerencia o processo de cadastro dos usuários compradores e vendedores que desejam comprar no
marketplace.

### Cadastro de usuário (2 pontos)

Permitir que os usuários possam se cadastrar no sistema.

### Cadastro de vendedores (2 pontos)

Permitir que vendedores possam se cadastrar no sistema.

### Gerenciamento de perfis de usuário (3 pontos)

Permitir que os usuários possam definir suas informações de perfil, como nome, endereço, informações de contato e
preferências de comunicação.

### Verificação de informações do vendedor (3 pontos)

Realizar a verificação de informações dos vendedores, como informações fiscais e bancárias, para garantir que estão
corretas e em conformidade com as leis aplicáveis.

**Total: 10 pontos**

---

## Suporte ao cliente

Este microsserviço gerencia as interações dos usuários com o suporte ao cliente, permitindo que os usuários abram
tickets de suporte, recebam respostas e acompanhem o status de suas solicitações.

### Solicitações (1 pontos)

Registrar as solicitações de suporte dos clientes;

* Permitir envio de fotos (1 ponto)
* Classificar as solicitações com base em sua natureza e gravidade (1 ponto);

### Gerenciamento de naturezas (3 pontos)

Permitir que os administradores cadastrem, alterem e excluem tipos de solicitações.

### Respostas (2 pontos)

Permitir que os administradores do sistema respondam às solicitações e encaminhem para os vendedores caso seja
necessário.

### Notificações (4 pontos)

Enviar emails aos usuários com atualizações de status das solicitações.

**Total: 12 pontos**

---

## Gerenciamento de frete

Este microsserviço gerencia o processo de cálculo e cobrança de frete para os produtos comprados no marketplace,
permitindo que os usuários escolham entre diferentes opções de envio e rastreiem o status de entrega de seus produtos.

### Cálculo de frete (3 pontos)

Calcular o custo do frete com base nas informações de entrega do cliente, peso e dimensões dos produtos e opções de
frete disponíveis.

### Seleção de frete (2 pontos)

Fornecer ao cliente opções de frete disponíveis com base em sua localização e tempo de entrega, permitindo que eles
selecionem a melhor opção para suas necessidades.

### Integração de transportadoras (3 pontos por transportadora)

Integrar-se com as transportadoras para realizar cálculos precisos de frete e obter informações de rastreamento
atualizadas.

### Rastreamento de frete (3 pontos)

Permitir que os clientes rastreiem o status de seus pedidos, fornecendo informações atualizadas sobre o envio e entrega
dos produtos.

### Relatórios de frete (2 pontos)

Manter um registro detalhado de todos os custos de frete, incluindo informações sobre transportadoras, custos de envio,
prazo de entrega, entre outros. Permitir que os administradores gerem relatórios com base nessas informações.

### Gerenciamento de problemas de entrega (1 ponto)

Gerenciar problemas de entrega, como atrasos ou extravios de encomendas, garantindo que o cliente receba o produto ou
seja reembolsado adequadamente.

**Total: pelo menos 14 pontos**

---

## Gerenciamento de promoções

Este microsserviço gerencia as promoções e descontos oferecidos aos usuários no marketplace, permitindo que os
proprietários do marketplace criem e gerenciem diferentes tipos de promoções para atrair mais usuários e aumentar as
vendas

### Criação de promoção (2 pontos)

capacidade de criar uma promoção com informações como desconto, produtos elegíveis, período de validade e código
promocional, se aplicável.

### Atualização de promoção (1 ponto)

capacidade de atualizar uma promoção existente com novas informações.

### Aplicação de promoção (2 pontos)

aplicar o desconto ou oferta especial automaticamente ao carrinho de compras do cliente quando as condições da promoção
são atendidas.

### Relatórios de promoções (3 pontos)

manter um registro detalhado de todas as promoções criadas e aplicadas, permitindo que os administradores gerem
relatórios com base nessas informações.

### Notificações (2 pontos)

enviar notificações por e-mail ou por meio de aplicativos para informar os clientes sobre as promoções disponíveis.

### Restrições (3 pontos)

permitir que os administradores restrinjam a aplicação de promoções com base em regras específicas, como limitações de
uso por cliente, produtos ou períodos de tempo.

## Lista de desejos

Este microsserviço gerencia a lista de desejos do usuário. Podendo adicionar, remover e compartilhar com outros
usuários.

### Adicionar produto à lista de desejos (2 pontos)

capacidade de adicionar um produto à lista de desejos do usuário, permitindo que eles salvem os produtos que desejam
comprar no futuro.

### Remover produto da lista de desejos (1 ponto)

capacidade de remover um produto da lista de desejos do usuário quando não desejar mais comprá-lo.

### Notificações de preço (4 pontos)

enviar notificações por e-mail ou por meio de aplicativos quando um produto da lista de desejos estiver com um preço
reduzido ou em promoção.

### Notificações de disponibilidade (4 pontos)

enviar notificações por e-mail ou por meio de aplicativos quando um produto da lista de desejos estiver disponível
novamente.

### Compartilhar lista de desejos (2 pontos)

capacidade de compartilhar a lista de desejos com outras pessoas, permitindo que amigos e familiares vejam o que o
usuário deseja comprar.

**Total: 14 pontos**

---

## Comunicação vendedor-comprador

Este microsserviço gerencia a comunicação entre comprador e vendedor para acertarem os detalhes da compra e para tirar
dúvidas do cliente.

### Mensagens (3 pontos)

Permitir que os compradores e vendedores enviem mensagens uns aos outros por meio da plataforma, garantindo que todas as
informações relevantes sejam mantidas no mesmo lugar e que a comunicação seja transparente.

* 6 pontos caso a comunicação seja feita em tempo-real.

### Notificações (4 pontos)

Enviar notificações aos compradores e vendedores quando novas mensagens são recebidas ou quando ocorrem mudanças no
status do pedido, garantindo que eles sejam informados sobre as atividades relevantes.

### Histórico de mensagens (2 pontos)

Manter um histórico de todas as mensagens enviadas e recebidas pelos compradores e vendedores, permitindo que eles
revisitem as conversas quando necessário.

### Gerenciamento de problemas (3 pontos)

Permitir que os compradores reportem problemas relacionados ao pedido, como produtos danificados ou entregas atrasadas,
e permitir que os vendedores respondam e resolvam esses problemas de forma eficiente.

**Total: 12 pontos**

---

## Busca de produtos

Este microsserviço vai ser responsável por realizar a busca de produtos conforme os filtros solicitados. As buscas devem
ser integradas com os serviços de Gerenciamento de Produtos e o Gerenciamento de Estoque

### Busca por palavra-chave (3 pontos)

Capacidade de pesquisar produtos por meio de uma palavra-chave, que pode ser o nome do produto, marca ou outra
informação relevante.

### Filtragem de produtos (3 pontos)

Permitir que os usuários filtrem produtos por preço, categoria, avaliação de usuários, entre outros critérios.

### Ordenação de resultados (1 ponto)

Permitir que os usuários ordenem os resultados da busca por preço, popularidade, avaliação, entre outros critérios.

### Sugestões de produtos (2 pontos)

Fornecer sugestões de produtos com base no histórico de busca do usuário ou em produtos relacionados ao que ele está
visualizando.

### Cache de pesquisas (4 pontos)

Capacidade de salvar as buscas em um cache para permitir uma maior performance nas buscas.

**Total 13 pontos**
