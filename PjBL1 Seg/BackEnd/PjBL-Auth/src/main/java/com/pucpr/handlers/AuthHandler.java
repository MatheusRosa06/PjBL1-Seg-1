package com.pucpr.handlers;

import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;


/**
 * Classe responsável por gerenciar as requisições de Autenticação.
 * Aqui o aluno aprenderá a manipular o corpo de requisições HTTP e
 * aplicar conceitos de hashing e proteção de dados.
 */
public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    /**
     * Gerencia o processo de Login.
     * Objetivo: Validar credenciais e emitir um passaporte (JWT).
     */
    public void handleLogin(HttpExchange exchange) throws IOException {
        // DICA DIDÁTICA: Em APIs REST, o Login sempre deve ser POST para
        // garantir que a senha viaje no corpo (body) e não na URL.
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1); // 405 Method Not Allowed
            return;
        }

        // TODO: O ALUNO DEVE IMPLEMENTAR OS SEGUINTES PASSOS:

        // 1. EXTRAÇÃO: Use exchange.getRequestBody() para ler os bytes do JSON enviado.
        InputStream bodyStream = exchange.getRequestBody();

        // 2. CONVERSÃO: Transforme esse JSON em um objeto (ex: LoginRequest) usando Jackson.
        // Primeiro, instanciamos o "tradutor" do Jackson
        ObjectMapper mapper = new ObjectMapper();
        // 2. CONVERSÃO: O mapper lê o stream e cria um objeto da classe Usuario
        Usuario loginRequest = mapper.readValue(bodyStream, Usuario.class);


        // 3. BUSCA E SEGURANÇA:
        //    a) Busque o usuário no 'repository' pelo e-mail fornecido.
        Usuario usuarioEncontrado = repository.findAll().stream()
                .filter(u -> u.getEmail().equalsIgnoreCase(loginRequest.getEmail()))
                .findFirst()
                .orElse(null);
        // b) Se existir, use BCrypt.checkpw(senhaInformada, senhaDoArquivo) para validar.
        // b) Se existir, use BCrypt.checkpw para validar
        if (usuarioEncontrado != null) {
            // Pegamos a senha que o usuário digitou no login (texto claro)
            String senhaInformada = loginRequest.getSenhaHash();
            // Pegamos o hash que está guardado no nosso arquivo JSON
            String senhaDoArquivo = usuarioEncontrado.getSenhaHash();
            // O BCrypt.checkpw faz a mágica de comparar os dois de forma segura
            if (BCrypt.checkpw(senhaInformada, senhaDoArquivo)) {
                // Senha correta! O fluxo segue para gerar o JWT
            } else {
                // Senha incorreta!
            }
        }

        // 4. REGRA DE OURO DA SEGURANÇA:
        //    - NUNCA use .equals() ou == para comparar senhas. O BCrypt é a sugestão.
        //    - Em caso de falha, retorne uma mensagem GENÉRICA (ex: "E-mail ou senha inválidos").
        //      Revelar qual dos dois está errado ajuda atacantes em técnicas de enumeração.
        if (usuarioEncontrado != null && BCrypt.checkpw(senhaInformada, senhaDoArquivo)) {
            // Caso de SUCESSO: O fluxo segue para gerar o JWT
        } else {
            // Caso de FALHA: Mensagem GENÉRICA para evitar "Enumeração de Usuários"
            String mensagemErro = "{\"error\": \"E-mail ou senha inválidos\"}";
            enviarResposta(exchange, 401, mensagemErro);
        }

        // 5. RESPOSTA:
        //    - Se as credenciais estiverem OK: Gere o Token via jwtService e retorne 200 OK.
        //    - Se falhar: Retorne 401 Unauthorized com o JSON de erro.
        if (usuarioEncontrado != null && BCrypt.checkpw(senhaInformada, senhaDoArquivo)) {
            // Caso SUCESSO: As credenciais estão OK
            // Geramos o token usando o e-mail e o cargo (role) do usuário [cite: 43]
            String token = jwtService.generateToken(usuarioEncontrado);
            // Criamos o JSON de resposta com o token
            String jsonSucesso = "{\"token\": \"" + token + "\"}";

            // Enviamos o status 200 OK
            enviarResposta(exchange, 200, jsonSucesso);
        } else {
            // Caso FALHA: Credenciais incorretas ou usuário inexistente
            // Mensagem genérica para evitar ataques de enumeração [cite: 57]
            String jsonErro = "{\"error\": \"E-mail ou senha inválidos\"}";

            // Enviamos o status 401 Unauthorized
            enviarResposta(exchange, 401, jsonErro);
        }
    }

    /**
     * Gerencia o processo de Cadastro (Registro).
     * Objetivo: Criar um novo usuário de forma segura.
     */
    public void handleRegister(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        // TODO: O ALUNO DEVE IMPLEMENTAR OS SEGUINTES PASSOS:

        // 1. VALIDAÇÃO DE EXISTÊNCIA:
        //    Antes de cadastrar, verifique se o e-mail já está em uso no 'repository'.
        //    Se já existir, interrompa e retorne 400 Bad Request.
        boolean usuarioJaExiste = repository.findAll().stream()
                .anyMatch(u -> u.getEmail().equalsIgnoreCase(novoUserReq.getEmail()));

        if (usuarioJaExiste) {
            // Se o e-mail já existir, interrompemos o processo
            String erroJson = "{\"error\": \"Este e-mail já está em uso.\"}";

            // Retornamos 400 Bad Request conforme a regra do projeto
            enviarResposta(exchange, 400, erroJson);
            return; // O 'return' é vital para parar a execução aqui
        }

        // 2. CRIPTOGRAFIA (Hashing):
        //    A senha recebida NUNCA deve chegar ao arquivo em texto claro.
        //    Gere o hash: BCrypt.hashpw(senhaPura, BCrypt.gensalt(12)).
        //    O "salt" (fator 12) protege contra ataques de Rainbow Tables.
        // Capturamos a senha que veio do JSON (ainda em texto claro neste momento)
        String senhaPura = novoUserReq.getSenhaHash();

        // Geramos o hash usando BCrypt com o fator de custo 12, conforme exigido
        // O "salt" aleatório é gerado e embutido automaticamente no resultado
        String senhaHasheada = BCrypt.hashpw(senhaPura, BCrypt.gensalt(12));

        // Agora a variável 'senhaHasheada' contém algo como "$2a$12$..."
        // e está pronta para ser guardada no objeto que irá para o repositório.

        // 3. PERSISTÊNCIA:
        //    Crie uma nova instância de Usuario (model) com a senha já HASHEADA.
        //    Use o repository.save(novoUsuario) para gravar no arquivo JSON.
        Usuario novoUsuarioParaSalvar = new Usuario(
                novoUserReq.getNome(),
                novoUserReq.getEmail(),
                senhaHasheada, // <--- Aqui está a segurança!
                novoUserReq.getRole()
        );

        // Chamamos o método do repositório para gravar no arquivo JSON
        repository.save(novoUsuarioParaSalvar);

        // 4. RESPOSTA: Se tudo der certo, retorne 201 Created.
        String jsonSucesso = "{\"message\": \"Usuário cadastrado com sucesso!\"}";

        // Enviamos o código HTTP 201 (Created), que é o padrão para novos recursos criados
        enviarResposta(exchange, 201, jsonSucesso);
    }
}