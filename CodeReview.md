# Code Review — Sistema de Gestão de Aluguel de Veículos

> **Revisão realizada com o agente `.agents/skills/code-review-expert`**
> Metodologia: SOLID Checklist · Security Checklist · Code Quality Checklist
> Severidades: **P0** Crítico | **P1** Alto | **P2** Médio | **P3** Baixo

---

## Sumário

| # | Severidade | Arquivo | Problema |
|---|-----------|---------|---------|
| 1 | P0 | `AuthController.java:34` / `StartupListener.java:67` | Senhas armazenadas em texto puro |
| 2 | P0 | `AuthController.java:43,53` | Token UUID sem assinatura nem expiração |
| 3 | P0 | Todos os controllers | Endpoints sem autenticação/autorização |
| 4 | P0 | `SimpleCorsFilter.java` | CORS com wildcard irrestrito |
| 5 | P1 | `PedidoService.java:16-20` | DIP: dependência de implementações concretas |
| 6 | P1 | `AuthController.java:36-40` | SRP: controller cria entidade de domínio |
| 7 | P1 | `PedidoController.java:48-67` | SRP: lógica de mapeamento no controller |
| 8 | P1 | `PedidoService.java:80-83` | OCP: regra de crédito hardcoded (Strategy Pattern) |
| 9 | P1 | `PedidoService.java:14-30` | God Service com 5 repositórios injetados |
| 10 | P1 | Arquitetura geral | Ausência de camada de domínio (Anemic Domain Model) |
| 11 | P2 | `Automovel.java:29`, `Pedido.java`, `Contrato.java` | Primitive Obsession: Double para dinheiro |
| 12 | P2 | `PedidoService.java:46-48` e `105-107` | Duplicação da lógica de cálculo de diárias |
| 13 | P2 | `Cliente.java` | FetchType.EAGER em OneToMany |
| 14 | P2 | `Automovel.java:27` | Associação fraca via ID primitivo |
| 15 | P2 | `AutomovelService.java:30,40` | Retorno null em vez de Optional |
| 16 | P2 | `PedidoService.java:32` | Ausência de @Transactional em criarPedido |
| 17 | P2 | `PedidoService.java:53`, `AutomovelService.java:25` | Listagem sem paginação |
| 18 | P2 | `StartupListener.java:64-76` | Credenciais hardcoded no seed de dados |
| 19 | P2 | DTOs e Controllers | Ausência de validação de entrada (Bean Validation) |
| 20 | P2 | `GlobalExceptionHandler.java` | Handler genérico que vaza informações internas |
| 21 | P3 | `GestaoAluguelVeiculosTest.java` | Cobertura de testes inexistente |
| 22 | P3 | `AuthController.java:45,54` | AuthResponse expõe entidade de domínio completa |

---

## Comentários Detalhados

---

### 🔴 P0 — Crítico

---

#### Comentário 1 — `AuthController.java:34` · `StartupListener.java:67`

🔍 **Sugestão de melhoria:** As senhas dos usuários são armazenadas e comparadas em texto puro. Em `AuthController.java:34` temos `usuario.setSenha(request.getSenha())` e em `AuthController.java:52` a comparação direta `.getSenha().equals(request.getSenha())`. O mesmo ocorre em `StartupListener.java:67` com `u.setSenha("1234")`. Isso viola o princípio de **defesa em profundidade** (Defense in Depth) e é uma das vulnerabilidades mais graves previstas no OWASP Top 10 (A02:2021 – Cryptographic Failures). Qualquer vazamento de banco de dados expõe imediatamente todas as senhas dos usuários.

📉 **Impacto/Benefícios da mudança:** Um atacante que obtenha acesso ao banco de dados (via SQL injection, backup exposto ou acesso interno) terá acesso imediato a todas as credenciais. Como usuários reutilizam senhas entre sistemas, o impacto vai muito além desta aplicação. Hashing com bcrypt introduz um custo computacional que torna ataques de força bruta inviáveis mesmo se o banco for comprometido. A testabilidade também melhora, pois o serviço de hash pode ser mockado em testes unitários.

📌 **Sugestão de implementação:**
```java
// Definir abstração seguindo DIP
public interface PasswordEncoder {
    String encode(String rawPassword);
    boolean matches(String rawPassword, String encodedPassword);
}

// Implementação com BCrypt
@Singleton
public class BCryptPasswordEncoder implements PasswordEncoder {
    private final BCrypt.Hasher hasher = BCrypt.withDefaults();
    private final BCrypt.Verifyer verifyer = BCrypt.verifyer();

    @Override
    public String encode(String rawPassword) {
        return hasher.hashToString(12, rawPassword.toCharArray());
    }

    @Override
    public boolean matches(String rawPassword, String encodedPassword) {
        return verifyer.verify(rawPassword.toCharArray(), encodedPassword).verified;
    }
}

// AuthController.java — uso correto:
usuario.setSenha(passwordEncoder.encode(request.getSenha())); // no registro
passwordEncoder.matches(request.getSenha(), user.getSenha()); // no login
```

---

#### Comentário 2 — `AuthController.java:43,53`

🔍 **Sugestão de melhoria:** O "token" gerado é um simples `UUID.randomUUID()` sem assinatura criptográfica, sem expiração e sem qualquer informação de identidade verificável. Nas linhas 43 e 53: `String token = UUID.randomUUID().toString()`. Um UUID não é um token de autenticação — é apenas um identificador aleatório. Nenhuma validação posterior desse token é feita nos endpoints protegidos, o que na prática significa que a autenticação é fictícia. O padrão consagrado para tokens stateless é **JWT (JSON Web Token)** com assinatura HMAC-SHA256 ou RSA.

📉 **Impacto/Benefícios da mudança:** Sem um token verificável, qualquer chamada aos endpoints pode ser feita por qualquer usuário simplesmente enviando qualquer string no header `Authorization`. JWT permite ao servidor verificar a identidade do chamador sem consultar o banco de dados a cada requisição (stateless), além de suportar expiração nativa com o campo `exp` e carregar claims de autorização como `role`. Isso melhora segurança, escalabilidade e rastreabilidade.

📌 **Sugestão de implementação:**
```java
// Micronaut Security possui suporte nativo a JWT.
// Em application.properties:
// micronaut.security.enabled=true
// micronaut.security.token.jwt.signatures.secret.generator.secret=${JWT_SECRET}
// micronaut.security.token.jwt.generator.access-token.expiration=3600

@Singleton
public class AuthService {
    private final JwtTokenGenerator tokenGenerator;

    public String gerarToken(Usuario usuario) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", usuario.getId().toString());
        claims.put("email", usuario.getEmail());
        claims.put("role", usuario.getTipoPerfil().name());
        return tokenGenerator.generateToken(claims)
            .orElseThrow(() -> new RuntimeException("Falha ao gerar token"));
    }
}
// Token resultante: eyJhbGciOiJIUzI1NiJ9... (assinado, com exp)
```

---

#### Comentário 3 — Todos os Controllers (`/api/**`)

🔍 **Sugestão de melhoria:** Nenhum endpoint da API possui verificação de autenticação ou autorização. Qualquer pessoa que conheça as URLs pode criar pedidos, listar todos os clientes, cadastrar automóveis e avaliar contratos sem estar autenticada. Por exemplo, `GET /api/clientes` lista todos os clientes sem exigir token. Isso viola o princípio **Fail Secure** e representa uma falha de **Broken Access Control (OWASP A01:2021)**. Há também ausência de **RBAC (Role-Based Access Control)**: um cliente pode chamar `POST /api/pedidos/{id}/avaliar`, que é uma operação exclusiva de agentes.

📉 **Impacto/Benefícios da mudança:** Sem controle de acesso, a aplicação é completamente aberta — qualquer usuário age como administrador. A adoção de guards de autenticação centraliza a política de segurança, evita duplicação de verificações nos services, e permite auditoria de acesso por role. O acoplamento entre lógica de negócio e regras de acesso é eliminado — o security framework cuida disso declarativamente.

📌 **Sugestão de implementação:**
```java
// Com Micronaut Security, basta anotar os controllers:

@Controller("/api/pedidos")
@Secured(SecurityRule.IS_AUTHENTICATED) // exige token válido para todos os métodos
public class PedidoController {

    @Post("/{id}/avaliar")
    @Secured("AGENTE") // apenas agentes podem avaliar
    public PedidoDTO avaliar(@PathVariable Long id,
                              @QueryValue Long agenteId,
                              @QueryValue boolean aprovar) { ... }

    @Post
    @Secured("CLIENTE") // apenas clientes criam pedidos
    public PedidoDTO criar(@Body CreatePedidoRequest request) { ... }
}

// Endpoints públicos (login/register):
@Controller("/auth")
@Secured(SecurityRule.IS_ANONYMOUS)
public class AuthController { ... }
```

---

#### Comentário 4 — `SimpleCorsFilter.java`

🔍 **Sugestão de melhoria:** A configuração CORS em `SimpleCorsFilter.java` define `Access-Control-Allow-Origin: *`, liberando o acesso à API de qualquer origem. Quando combinado com o envio de credenciais (cookies, tokens de autenticação via header), isso representa uma vulnerabilidade grave de Cross-Origin Resource Sharing. Adicionalmente, o filtro foi implementado manualmente, ignorando a configuração nativa do Micronaut que oferece suporte robusto a CORS com allowlist de origens.

📉 **Impacto/Benefícios da mudança:** Um wildcard CORS com credentials habilitadas permite que qualquer site malicioso faça requisições autenticadas à API em nome do usuário logado (vetor CSRF via CORS). Restringir as origens a domínios conhecidos elimina esse vetor. Usar a configuração nativa do Micronaut é mais manutenível, auditável e elimina o filtro customizado que pode ter comportamentos inesperados na cadeia de execução.

📌 **Sugestão de implementação:**
```properties
# application.properties — substituir SimpleCorsFilter por configuração nativa:
micronaut.server.cors.enabled=true
micronaut.server.cors.configurations.web.allowed-origins=https://meu-frontend.com
micronaut.server.cors.configurations.web.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
micronaut.server.cors.configurations.web.allowed-headers=Content-Type,Authorization,Accept
micronaut.server.cors.configurations.web.allow-credentials=true
micronaut.server.cors.configurations.web.max-age=3600
```
```java
// SimpleCorsFilter.java pode ser removido completamente após a configuração acima.
// Para ambiente de desenvolvimento, usar um perfil separado:
// application-dev.properties com allowed-origins=http://localhost:5173
```

---

### 🟠 P1 — Alto

---

#### Comentário 5 — `PedidoService.java:16-20`

🔍 **Sugestão de melhoria:** `PedidoService` depende diretamente das implementações concretas dos repositórios (`PedidoRepository`, `ClienteRepository`, `AutomovelRepository`, `ContratoRepository` e `AgenteRepository`). Não há nenhuma interface intermediária entre a camada de serviço e a camada de persistência. Isso viola o **Princípio da Inversão de Dependência (DIP — SOLID "D")**: módulos de alto nível (serviços de negócio) devem depender de abstrações, não de implementações concretas de infraestrutura.

📉 **Impacto/Benefícios da mudança:** A ausência de interfaces torna os serviços impossíveis de testar unitariamente sem subir o contexto do Micronaut e uma base de dados real. Qualquer troca de tecnologia de persistência (ex.: migrar de JPA para JDBC puro, ou usar repositório in-memory para testes) exige modificação direta nos serviços. Com interfaces, basta trocar a implementação injetada. A testabilidade melhora drasticamente — é possível criar mocks que retornam dados controlados sem dependências externas.

📌 **Sugestão de implementação:**
```java
// Definir interfaces de domínio (Ports — nomenclatura Hexagonal Architecture):
// br.gestao.service.port

public interface PedidoRepositoryPort {
    Optional<Pedido> findById(Long id);
    Pedido save(Pedido pedido);
    Pedido update(Pedido pedido);
    void deleteById(Long id);
    List<Pedido> findAll();
}

// A implementação JPA fica na camada de infraestrutura:
@Repository
public class PedidoRepositoryAdapter
    implements PedidoRepositoryPort, CrudRepository<Pedido, Long> {
    // Micronaut Data implementa os métodos automaticamente
}

// PedidoService passa a depender da abstração:
@Singleton
public class PedidoService {
    private final PedidoRepositoryPort pedidoRepository; // interface, não implementação
    private final ClienteRepositoryPort clienteRepository;
    // ...
}
```

---

#### Comentário 6 — `AuthController.java:36-40`

🔍 **Sugestão de melhoria:** O `AuthController` viola o **Single Responsibility Principle (SRP)** ao conter lógica de criação de entidades de domínio (`Cliente`, `Usuario`) diretamente no controller. Nas linhas 36-40 vemos `Cliente cliente = new Cliente(); cliente.setNome(...)`. Um controller HTTP tem como única responsabilidade fazer o binding da requisição HTTP e delegar ao serviço adequado — nunca instanciar e orquestrar a criação de agregados de domínio.

📉 **Impacto/Benefícios da mudança:** A lógica de criação de usuário/cliente está no controller, o que significa que ela não pode ser reutilizada por outros mecanismos de entrada (CLI, event listener, outro controller). Testes unitários do fluxo de registro exigem subir o contexto HTTP completo. Mover essa lógica para um `AuthService` deixa o controller fino e coeso, e permite testar o registro isoladamente com um mock de repositório.

📌 **Sugestão de implementação:**
```java
// AuthService.java — responsável pela lógica de registro e login
@Singleton
public class AuthService {
    private final UsuarioRepository usuarioRepository;
    private final ClienteRepository clienteRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponse registrar(RegisterRequest request) {
        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("E-mail já está em uso.");
        }
        Usuario usuario = new Usuario();
        usuario.setNome(request.getNome());
        usuario.setEmail(request.getEmail());
        usuario.setSenha(passwordEncoder.encode(request.getSenha()));

        Cliente cliente = new Cliente();
        cliente.setNome(usuario.getNome());
        cliente.setUsuario(usuario);
        clienteRepository.save(cliente);
        return new AuthResponse(gerarToken(usuario), UsuarioDTO.from(usuario));
    }
}

// AuthController.java — apenas recebe e delega:
@Post("/register")
public HttpResponse<?> register(@Body @Valid RegisterRequest request) {
    return HttpResponse.ok(authService.registrar(request));
}
```

---

#### Comentário 7 — `PedidoController.java:48-67`

🔍 **Sugestão de melhoria:** O método privado `toDTO(Pedido pedido)` nas linhas 48-67 do `PedidoController` implementa 20 linhas de lógica de mapeamento entre entidade e DTO, incluindo tratamento de nulos e regras condicionais. Isso viola o **SRP**: o controller acumula a responsabilidade de transformação de dados. O padrão adequado é o **Mapper/Assembler**, podendo ser implementado com MapStruct ou manualmente em uma classe dedicada.

📉 **Impacto/Benefícios da mudança:** Quando a estrutura do DTO ou da entidade mudar, o controller precisa ser modificado — violando novamente o SRP. Se outro controller precisar do mesmo mapeamento, o código é duplicado. Um `PedidoMapper` pode ser testado isoladamente, reutilizado em múltiplos controllers e facilmente substituído por uma implementação gerada (MapStruct) sem alterar o controller.

📌 **Sugestão de implementação:**
```java
// PedidoMapper.java — classe dedicada ao mapeamento
@Singleton
public class PedidoMapper {
    public PedidoDTO toDTO(Pedido pedido) {
        PedidoDTO dto = new PedidoDTO();
        dto.setId(pedido.getId());
        dto.setClienteId(resolveClienteId(pedido));
        dto.setAutomovelId(pedido.getAutomovel().getId());
        dto.setAutomovelMarca(pedido.getAutomovel().getMarca());
        dto.setAutomovelModelo(pedido.getAutomovel().getModelo());
        dto.setDataInicio(pedido.getDataInicio());
        dto.setDataFim(pedido.getDataFim());
        dto.setStatus(pedido.getStatus().name());
        dto.setValorTotal(pedido.getValorTotal());
        dto.setValorDiaria(pedido.getAutomovel().getValorDiaria());
        return dto;
    }

    private Long resolveClienteId(Pedido pedido) {
        if (pedido.getCliente() == null) return null;
        return pedido.getCliente().getUsuario() != null
            ? pedido.getCliente().getUsuario().getId()
            : pedido.getCliente().getId();
    }
}

// PedidoController.java — delega ao mapper injetado:
private final PedidoMapper mapper;

@Get
public List<PedidoDTO> listar() {
    return pedidoService.listarTodos().stream()
        .map(mapper::toDTO)
        .collect(Collectors.toList());
}
```

---

#### Comentário 8 — `PedidoService.java:80-83`

🔍 **Sugestão de melhoria:** A regra de negócio "se o agente é um banco, concede crédito" está implementada como um `if` direto dentro de `avaliarPedido()` nas linhas 80-83: `if (agente.getTipoAgente() == TipoAgente.BANCO)`. Isso viola o **Open/Closed Principle (OCP)**: a classe está fechada para extensão, pois qualquer novo tipo de avaliação (ex.: agente EMPRESA com critérios diferentes, score de crédito) exige modificar o método existente. O padrão **Strategy** é o indicado para encapsular algoritmos de avaliação intercambiáveis.

📉 **Impacto/Benefícios da mudança:** À medida que regras de negócio evoluem, `avaliarPedido` cresce indefinidamente com `if/else` encadeados — um anti-padrão clássico. Com o padrão Strategy, cada regra de avaliação vive em sua própria classe, pode ser testada isoladamente e adicionada sem modificar código existente. O `PedidoService` deixa de ter responsabilidade sobre o "como" avaliar, apenas sobre o "quando" e "para quem" delegar.

📌 **Sugestão de implementação:**
```java
// AvaliacaoStrategy.java — interface do padrão Strategy
public interface AvaliacaoStrategy {
    boolean suporta(TipoAgente tipo);
    Contrato gerarContrato(Pedido pedido, Agente agente);
}

// BancoAvaliacaoStrategy.java
@Singleton
public class BancoAvaliacaoStrategy implements AvaliacaoStrategy {
    @Override
    public boolean suporta(TipoAgente tipo) { return tipo == TipoAgente.BANCO; }

    @Override
    public Contrato gerarContrato(Pedido pedido, Agente agente) {
        Contrato contrato = new Contrato();
        contrato.setPedido(pedido);
        contrato.setValorTotal(pedido.getValorTotal());
        contrato.setIsCreditoConcedido(true);
        contrato.setBanco(agente);
        return contrato;
    }
}

// EmpresaAvaliacaoStrategy.java
@Singleton
public class EmpresaAvaliacaoStrategy implements AvaliacaoStrategy {
    @Override
    public boolean suporta(TipoAgente tipo) { return tipo == TipoAgente.EMPRESA; }

    @Override
    public Contrato gerarContrato(Pedido pedido, Agente agente) {
        Contrato contrato = new Contrato();
        contrato.setPedido(pedido);
        contrato.setValorTotal(pedido.getValorTotal());
        contrato.setIsCreditoConcedido(false);
        return contrato;
    }
}

// PedidoService.java — seleciona a strategy adequada:
private final List<AvaliacaoStrategy> strategies;

private Contrato criarContrato(Pedido pedido, Agente agente) {
    return strategies.stream()
        .filter(s -> s.suporta(agente.getTipoAgente()))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Nenhuma estratégia para: " + agente.getTipoAgente()))
        .gerarContrato(pedido, agente);
}
```

---

#### Comentário 9 — `PedidoService.java:14-30`

🔍 **Sugestão de melhoria:** `PedidoService` injeta **cinco repositórios** diferentes: `PedidoRepository`, `ClienteRepository`, `AutomovelRepository`, `ContratoRepository` e `AgenteRepository`. Este é um forte sintoma de **God Service** — uma classe que sabe demais e faz demais. O code smell **Feature Envy** também está presente: o serviço precisa conhecer profundamente a estrutura interna de `Cliente`, `Automovel`, `Agente` e `Contrato` para executar suas operações, em vez de delegar para os serviços especializados dessas entidades.

📉 **Impacto/Benefícios da mudança:** Um serviço com muitas dependências tem muitos motivos para mudar (viola SRP), é difícil de testar (requer muitos mocks) e é um indicativo de acoplamento excessivo entre módulos. Idealmente, `PedidoService` deveria conversar com `ClienteService`, `AutomovelService` e `ContratoService` — não com os repositórios deles diretamente. Isso estabelece fronteiras de responsabilidade claras e facilita a evolução independente de cada módulo.

📌 **Sugestão de implementação:**
```java
// PedidoService.java refatorado — depende de serviços, não de repositórios alheios:
@Singleton
public class PedidoService {
    private final PedidoRepository pedidoRepository;  // próprio
    private final ClienteService clienteService;       // delega busca de cliente
    private final AutomovelService automovelService;   // delega busca de automovel
    private final ContratoService contratoService;     // delega criação de contrato
    private final AgenteService agenteService;         // delega busca de agente
    private final List<AvaliacaoStrategy> strategies;

    public Pedido criarPedido(CreatePedidoRequest request) {
        Cliente cliente = clienteService.buscarPorUsuarioIdOrThrow(request.getClienteId());
        Automovel automovel = automovelService.buscarPorIdOrThrow(request.getAutomovelId());
        // lógica exclusiva de Pedido aqui
    }
}
```

---

#### Comentário 10 — Arquitetura Geral (todos os pacotes)

🔍 **Sugestão de melhoria:** O projeto não possui separação de camadas de domínio. Toda a lógica de negócio está misturada entre controllers, services e entidades JPA. Nenhum dos objetos de domínio (`Pedido`, `Cliente`, `Automovel`) possui comportamento próprio; são simples sacos de dados — o anti-padrão **Anemic Domain Model** identificado por Martin Fowler. A estrutura atual é uma camada única (controller → service → repository) sem distinção entre regras de negócio e infraestrutura. O padrão **Hexagonal Architecture (Ports & Adapters)** ou mesmo uma separação em **Domain / Application / Infrastructure** resolveria isso de forma incremental.

📉 **Impacto/Benefícios da mudança:** Quando as regras de negócio residem apenas nas entidades JPA, qualquer mudança de framework ou banco de dados quebra o domínio. A lógica de negócio torna-se impossível de testar sem infraestrutura. Com uma camada de domínio rica, as regras vivem em objetos puros (POJOs sem anotações de framework), testáveis com JUnit puro, e a infraestrutura (JPA, HTTP, banco de dados) fica na periferia do sistema.

📌 **Sugestão de implementação:**
```
// Estrutura de pacotes proposta (Hexagonal / Clean Architecture):

br.gestao/
├── domain/                      <- Domínio puro, zero dependência de framework
│   ├── model/                   <- Entidades com comportamento real
│   │   ├── Pedido.java          <- Tem método: aprovar(), rejeitar(), calcularTotal()
│   │   └── Cliente.java         <- Tem método: adicionarRendimento(), totalRendimentos()
│   ├── port/                    <- Interfaces (Ports)
│   │   ├── PedidoRepository.java
│   │   └── NotificacaoService.java
│   └── service/                 <- Use Cases
│       └── AvaliarPedidoUseCase.java
└── infrastructure/              <- Adapters (JPA, HTTP, etc.)
    ├── persistence/
    │   └── JpaPedidoRepository.java  <- implementa domain.port.PedidoRepository
    └── web/
        └── PedidoController.java

// Exemplo de entidade de domínio rica:
public class Pedido {
    public void aprovar(Agente agente, AvaliacaoStrategy strategy) {
        if (this.status != StatusPedido.PENDENTE) {
            throw new IllegalStateException("Pedido já foi decidido: " + this.status);
        }
        this.agenteAvaliador = agente;
        this.status = StatusPedido.APROVADO;
        this.contrato = strategy.gerarContrato(this, agente);
    }

    public void calcularTotal() {
        long dias = Math.max(1, ChronoUnit.DAYS.between(dataInicio, dataFim));
        this.valorTotal = this.automovel.getValorDiaria().multiply(BigDecimal.valueOf(dias));
    }
}
```

---

### 🟡 P2 — Médio

---

#### Comentário 11 — `Automovel.java:29` · `Pedido.java` · `Contrato.java`

🔍 **Sugestão de melhoria:** Valores monetários (`valorDiaria`, `valorTotal`) são representados com o tipo primitivo `Double`. Isso caracteriza o code smell **Primitive Obsession** e viola boas práticas de modelagem financeira. O tipo `Double` usa representação de ponto flutuante binário (IEEE 754), causando erros de arredondamento em operações decimais — por exemplo, `0.1 + 0.2 != 0.3` em Java. Para valores monetários, o padrão consolidado é `BigDecimal` ou um Value Object `Money`.

📉 **Impacto/Benefícios da mudança:** Em um sistema de aluguel, cálculos com `Double` podem resultar em cobranças incorretas por arredondamento acumulado (ex.: `100.0 * 0.1 = 9.999999999999998` em vez de `10.00`). `BigDecimal` garante precisão arbitrária e controle explícito do modo de arredondamento (`RoundingMode.HALF_UP`). Um Value Object `Money` também elimina a possibilidade de somar valores em moedas diferentes inadvertidamente.

📌 **Sugestão de implementação:**
```java
// Opção 1 (mínima): Substituir Double por BigDecimal
@Entity
public class Automovel {
    @Column(precision = 10, scale = 2)
    private BigDecimal valorDiaria; // em vez de Double
}

// Opção 2 (preferida): Value Object imutável
public final class Money {
    private final BigDecimal valor;

    public Money(BigDecimal valor) {
        Objects.requireNonNull(valor, "Valor monetário não pode ser nulo");
        this.valor = valor.setScale(2, RoundingMode.HALF_UP);
    }

    public Money multiplicar(long fator) {
        return new Money(valor.multiply(BigDecimal.valueOf(fator)));
    }

    public Money somar(Money outro) {
        return new Money(valor.add(outro.valor));
    }

    @Override
    public boolean equals(Object o) { /* comparação por valor */ }
}

// Uso no cálculo:
Money total = automovel.getValorDiaria().multiplicar(dias);
pedido.setValorTotal(total);
```

---

#### Comentário 12 — `PedidoService.java:46-48` e `105-107`

🔍 **Sugestão de melhoria:** A lógica de cálculo do valor total do pedido (`dias * valorDiaria`, com mínimo de 1 diária) está duplicada em dois métodos: `criarPedido()` (linhas 46-48) e `atualizarPedido()` (linhas 105-107). O código é byte-a-byte idêntico. Isso viola o princípio **DRY (Don't Repeat Yourself)** e representa o code smell **Duplicação de Código**. Qualquer mudança na regra de cálculo (ex.: desconto para mais de 7 dias, taxa adicional para finais de semana) deve ser feita em dois lugares, com risco real de inconsistência.

📉 **Impacto/Benefícios da mudança:** Duplicação de lógica de negócio é uma das principais fontes de bugs: um lugar é corrigido, o outro esquecido. Extrair o cálculo para um método privado coeso — ou melhor ainda, para o próprio objeto de domínio `Pedido` — garante que a regra viva em um único lugar, seja facilmente testável e evolua de forma consistente em toda a aplicação.

📌 **Sugestão de implementação:**
```java
// Opção 1: método privado no service
private double calcularValorTotal(LocalDate dataInicio, LocalDate dataFim, Double valorDiaria) {
    long dias = ChronoUnit.DAYS.between(dataInicio, dataFim);
    if (dias <= 0) dias = 1;
    return dias * (valorDiaria != null ? valorDiaria : 0.0);
}

// criarPedido():
pedido.setValorTotal(calcularValorTotal(
    pedido.getDataInicio(), pedido.getDataFim(), automovel.getValorDiaria()
));

// atualizarPedido():
pedido.setValorTotal(calcularValorTotal(
    pedido.getDataInicio(), pedido.getDataFim(), automovel.getValorDiaria()
));

// Opção 2 (melhor — domínio rico): mover para a entidade Pedido
public class Pedido {
    public void recalcularTotal() {
        long dias = Math.max(1, ChronoUnit.DAYS.between(dataInicio, dataFim));
        this.valorTotal = dias * (automovel.getValorDiaria() != null ? automovel.getValorDiaria() : 0.0);
    }
}
// Uso: pedido.recalcularTotal(); — em ambos os métodos do service
```

---

#### Comentário 13 — `Cliente.java` (campo `rendimentos`)

🔍 **Sugestão de melhoria:** O relacionamento `@OneToMany` entre `Cliente` e `Rendimento` usa `FetchType.EAGER`. Isso significa que **toda vez** que um `Cliente` for carregado do banco de dados, todos os seus rendimentos são carregados automaticamente — mesmo que a operação não precise deles. Em sistemas com muitos clientes ou com histórico extenso de rendimentos, isso causa degradação de performance progressiva. `FetchType.LAZY` é o padrão recomendado para `@OneToMany` por razões de performance.

📉 **Impacto/Benefícios da mudança:** Com EAGER, uma listagem de 1000 clientes resulta em N+1 queries ou um JOIN que multiplica o volume de dados retornado pelo banco. Com LAZY, os rendimentos só são carregados quando explicitamente acessados no código, reduzindo drasticamente o volume de dados transferidos. A performance melhora proporcionalmente ao número de registros e à cardinalidade do relacionamento.

📌 **Sugestão de implementação:**
```java
// Cliente.java — alterar para LAZY (que inclusive é o padrão JPA):
@OneToMany(
    mappedBy = "cliente",
    cascade = CascadeType.ALL,
    orphanRemoval = true,
    fetch = FetchType.LAZY  // era FetchType.EAGER
)
private List<Rendimento> rendimentos = new ArrayList<>();

// Para carregar rendimentos quando necessário, usar JOIN FETCH:
// ClienteRepository.java
@Query("SELECT c FROM Cliente c LEFT JOIN FETCH c.rendimentos WHERE c.id = :id")
Optional<Cliente> findByIdComRendimentos(Long id);

// ClienteService.java — usar a query correta conforme o caso de uso:
public Cliente buscarComRendimentos(Long id) {
    return clienteRepository.findByIdComRendimentos(id)
        .orElseThrow(() -> new IllegalArgumentException("Cliente não encontrado"));
}
```

---

#### Comentário 14 — `Automovel.java:27`

🔍 **Sugestão de melhoria:** O campo `proprietarioId` (linha 27) armazena o ID do proprietário como um `Long` primitivo, sem nenhuma associação JPA real. Isso é um **código de chave estrangeira fantasma**: o banco não tem FK, não há integridade referencial e o código precisa saber externamente que esse ID pode se referir a um `Cliente` ou `Agente` dependendo do valor de `tipoProprietario`. Este é um code smell de **Primitive Obsession** combinado com **Código Frágil** — uma deleção de qualquer entidade proprietária não causa erro no banco, deixando dados órfãos silenciosamente.

📉 **Impacto/Benefícios da mudança:** Sem integridade referencial, é possível ter um `Automovel` com `proprietarioId` apontando para um registro deletado. Qualquer código que use esse campo precisa verificar `tipoProprietario` antes de saber qual repositório consultar — lógica dispersa e propensa a erros. Um modelo com associações JPA explícitas garante integridade pelo banco e elimina a necessidade de lógica condicional no código.

📌 **Sugestão de implementação:**
```java
// Automovel.java — substituir o Long primitivo por associações explícitas:
@Entity
public class Automovel {
    // Remover: private Long proprietarioId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cliente_proprietario_id")
    private Cliente clienteProprietario;  // nullable — preenchido quando tipoProprietario = CLIENTE

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "agente_proprietario_id")
    private Agente agenteProprietario;   // nullable — preenchido quando tipoProprietario = BANCO ou EMPRESA

    // O tipoProprietario ainda é útil para lógica condicional,
    // mas agora é consistente com as FKs reais do banco.
}
```

---

#### Comentário 15 — `AutomovelService.java:30,40`

🔍 **Sugestão de melhoria:** Os métodos `buscarPorId()` (linha 30) e `atualizar()` (linha 40) retornam `null` quando o recurso não é encontrado: `return automovelRepository.findById(id).orElse(null)` e `return null`. Retornar `null` viola as boas práticas modernas do Java que exigem o uso de `Optional<T>` para representar ausência de valor, além do **Null Object Pattern**. O compilador Java não força o tratamento de `null` retornado — e quando o chamador esquece de verificar, ocorre `NullPointerException` em produção.

📉 **Impacto/Benefícios da mudança:** Com `Optional<Automovel>`, o compilador (e a API) comunicam explicitamente que o valor pode estar ausente, e o chamador é obrigado a tratar os dois casos. Isso elimina NPEs silenciosas e torna o contrato do método auto-documentado. O controller também pode retornar HTTP 404 adequado em vez de HTTP 500 por NullPointerException.

📌 **Sugestão de implementação:**
```java
// AutomovelService.java — retornar Optional ou lançar exceção descritiva:

// Opção 1: Optional (quando ausência é válida)
public Optional<Automovel> buscarPorId(Long id) {
    return automovelRepository.findById(id);
}

// Opção 2: lançar exceção com mensagem clara (quando ausência é erro)
public Automovel buscarPorIdOrThrow(Long id) {
    return automovelRepository.findById(id)
        .orElseThrow(() -> new IllegalArgumentException("Automóvel não encontrado: " + id));
}

public Optional<Automovel> atualizar(Long id, Automovel automovel) {
    if (!automovelRepository.existsById(id)) return Optional.empty();
    automovel.setId(id);
    return Optional.of(automovelRepository.update(automovel));
}

// AutomovelController.java — tratar o Optional adequadamente:
@Get("/{id}")
public HttpResponse<Automovel> buscar(@PathVariable Long id) {
    return automovelService.buscarPorId(id)
        .map(HttpResponse::ok)
        .orElse(HttpResponse.notFound());
}
```

---

#### Comentário 16 — `PedidoService.java:32`

🔍 **Sugestão de melhoria:** O método `criarPedido()` (linha 32) não possui a anotação `@Transactional`. Esse método realiza leituras de `Cliente` e `Automovel` e em seguida grava o novo `Pedido`. Se a operação de `save` falhar após as leituras (ex.: constraint de banco, falha de rede), não há garantia de rollback. Comparando com `avaliarPedido()` e `cancelarPedido()` — que possuem `@Transactional` — há uma inconsistência que indica falta de critério na aplicação da annotation. O método `atualizarPedido()` também não possui `@Transactional`.

📉 **Impacto/Benefícios da mudança:** Sem `@Transactional`, uma falha parcial durante a criação do pedido pode deixar o banco em estado inconsistente. A annotation também garante que todas as leituras da transação verão os mesmos dados (isolation level configurável), evitando leituras sujas em cenários concorrentes. A consistência das operações fica garantida pelo banco, não pelo código da aplicação.

📌 **Sugestão de implementação:**
```java
// PedidoService.java — adicionar @Transactional onde falta:

@Transactional  // ADICIONAR — cria pedido atomicamente
public Pedido criarPedido(CreatePedidoRequest request) {
    Cliente cliente = clienteRepository.findByUsuarioId(request.getClienteId())
        .orElseThrow(() -> new IllegalArgumentException("Cliente não encontrado"));
    Automovel automovel = automovelRepository.findById(request.getAutomovelId())
        .orElseThrow(() -> new IllegalArgumentException("Automóvel não encontrado"));
    // ... resto do método
}

@Transactional  // ADICIONAR — atualiza atomicamente
public Pedido atualizarPedido(Long id, CreatePedidoRequest request) {
    // ... método existente
}

// Já possuem @Transactional (corretos):
// avaliarPedido() — linha 57
// cancelarPedido() — linha 112
```

---

#### Comentário 17 — `PedidoService.java:53` · `AutomovelService.java:25`

🔍 **Sugestão de melhoria:** Os métodos `listarTodos()` em `PedidoService` e `AutomovelService` retornam **todas as entidades** sem nenhuma paginação: `return (List<Pedido>) pedidoRepository.findAll()`. Em produção, com centenas ou milhares de registros, isso carrega toda a tabela na memória da JVM e retorna no payload HTTP. A ausência de paginação é um anti-padrão que causa degradação de performance progressiva e pode resultar em `OutOfMemoryError` com volumes elevados de dados.

📉 **Impacto/Benefícios da mudança:** Uma tabela com 10.000 pedidos retornaria todas as linhas em uma única requisição, causando alto consumo de memória, timeout no cliente e payload HTTP potencialmente gigantesco. Paginação é uma prática fundamental de APIs REST escaláveis. Com `Pageable` do Micronaut Data, o banco executa `LIMIT/OFFSET`, devolvendo apenas o slice de dados solicitado, com metadata de navegação.

📌 **Sugestão de implementação:**
```java
// PedidoRepository.java — herdar de PageableRepository:
@Repository
public interface PedidoRepository extends PageableRepository<Pedido, Long> {}

// PedidoService.java:
public Page<Pedido> listarTodos(Pageable pageable) {
    return pedidoRepository.findAll(pageable);
}

// PedidoController.java:
@Get
public Page<PedidoDTO> listar(
    @QueryValue(defaultValue = "0") int page,
    @QueryValue(defaultValue = "20") int size) {
    Pageable pageable = Pageable.from(page, size, Sort.of(Sort.Order.desc("id")));
    return pedidoService.listarTodos(pageable).map(mapper::toDTO);
}
// Resposta: { "content": [...], "totalElements": 150, "totalPages": 8, "number": 0 }
```

---

#### Comentário 18 — `StartupListener.java:64-76`

🔍 **Sugestão de melhoria:** O `StartupListener` cria um usuário administrador com email e senha hardcoded diretamente no código-fonte (linhas 64-68): `u.setEmail("admin@localiza.com")` e `u.setSenha("1234")`. Isso viola o princípio de **Secrets Management**: credenciais nunca devem estar em repositórios de código. A senha `1234` é trivialmente fraca e amplamente testada em ataques de dicionário. Mesmo sendo seed de desenvolvimento, esse código frequentemente é esquecido e vaza para ambientes de produção.

📉 **Impacto/Benefícios da mudança:** Qualquer pessoa com acesso ao repositório GitHub tem as credenciais de administrador. Ferramentas de scanning de secrets (truffleHog, GitHub Secret Scanning) detectam padrões como `setSenha("1234")` e emitem alertas de vulnerabilidade. Mover credenciais iniciais para variáveis de ambiente garante que cada ambiente tenha suas próprias credenciais e que elas nunca apareçam no histórico git.

📌 **Sugestão de implementação:**
```properties
# application.properties — credentials via environment variables:
seed.admin.email=${SEED_ADMIN_EMAIL:admin@localiza.com}
seed.admin.senha=${SEED_ADMIN_SENHA:changeme123!}
```

```java
// StartupListener.java — injetar via @Value:
@Value("${seed.admin.email}")
private String adminEmail;

@Value("${seed.admin.senha}")
private String adminSenha;

// onApplicationEvent():
u.setEmail(adminEmail);
u.setSenha(passwordEncoder.encode(adminSenha)); // hash obrigatório — nunca texto puro

// Em CI/CD, definir como variável de ambiente segura:
// export SEED_ADMIN_EMAIL=admin@empresa.com
// export SEED_ADMIN_SENHA=$(openssl rand -base64 24)
```

---

#### Comentário 19 — DTOs e Controllers (Bean Validation ausente)

🔍 **Sugestão de melhoria:** Nenhum DTO do projeto possui anotações de **Bean Validation** (`@NotNull`, `@NotBlank`, `@Email`, `@Size`, `@Positive`). Por exemplo, `RegisterRequest` aceita email vazio, senha de 1 caractere ou nome nulo. `CreatePedidoRequest` aceita datas em qualquer formato de string sem validação. Os controllers também não usam `@Valid` para ativar a validação automática. Isso viola o princípio **Fail Fast** (falhar rápido na borda do sistema) e delega erros de validação para camadas mais profundas, onde produzem mensagens genéricas difíceis de debugar.

📉 **Impacto/Benefícios da mudança:** Sem validação na entrada, strings inválidas chegam ao banco (causando erros de constraint), datas malformadas lançam `DateTimeParseException` sem contexto e campos nulos causam NPEs nos services. Com Bean Validation, erros são detectados na borda do sistema (HTTP 400 com mensagens claras) antes de qualquer lógica de negócio ser executada, protegendo os services de dados corrompidos e melhorando drasticamente a experiência do cliente da API.

📌 **Sugestão de implementação:**
```java
// RegisterRequest.java — adicionar validações:
@Serdeable
public class RegisterRequest {
    @NotBlank(message = "Nome é obrigatório")
    @Size(min = 2, max = 100, message = "Nome deve ter entre 2 e 100 caracteres")
    private String nome;

    @NotBlank
    @Email(message = "Formato de e-mail inválido")
    private String email;

    @NotBlank
    @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres")
    private String senha;
}

// CreatePedidoRequest.java:
public class CreatePedidoRequest {
    @NotNull @Positive
    private Long automovelId;

    @NotNull @Positive
    private Long clienteId;

    @NotBlank
    @Pattern(regexp = "\\d{4}-\\d{2}-\\d{2}", message = "Data deve estar no formato YYYY-MM-DD")
    private String dataInicio;

    @NotBlank
    @Pattern(regexp = "\\d{4}-\\d{2}-\\d{2}")
    private String dataFim;
}

// AuthController.java — ativar validação com @Valid:
@Post("/register")
public HttpResponse<?> register(@Body @Valid RegisterRequest request) { ... }
```

---

#### Comentário 20 — `GlobalExceptionHandler.java`

🔍 **Sugestão de melhoria:** O `GlobalExceptionHandler` captura `RuntimeException` de forma genérica e retorna HTTP 500 com a mensagem de exceção diretamente no corpo da resposta. Isso viola dois princípios: **Information Hiding** (vazamento de detalhes internos para o cliente) e a separação entre erros de negócio e erros de infraestrutura. A mensagem de uma `NullPointerException`, `HibernateException` ou `ConstraintViolationException` não deve jamais ser exposta ao frontend — revela detalhes que podem ser explorados por atacantes.

📉 **Impacto/Benefícios da mudança:** Stack traces ou mensagens de exceção internas revelam tecnologias utilizadas (`hibernate`, `postgresql`), estrutura de pacotes e possíveis vetores de ataque. Um handler robusto mapeia tipos específicos de exceção para respostas HTTP padronizadas, registra os detalhes internamente no log com contexto de debugging, e retorna ao cliente apenas uma mensagem amigável com um código de erro estruturado e auditável.

📌 **Sugestão de implementação:**
```java
// ErrorResponse.java — DTO padronizado de erro
@Serdeable
public record ErrorResponse(String codigo, String mensagem, Instant timestamp) {
    public static ErrorResponse of(String codigo, String mensagem) {
        return new ErrorResponse(codigo, mensagem, Instant.now());
    }
}

// GlobalExceptionHandler.java — handlers específicos por tipo de exceção:
@Produces(MediaType.APPLICATION_JSON)
@Singleton
public class GlobalExceptionHandler {

    @Error(global = true, exception = IllegalArgumentException.class)
    public HttpResponse<ErrorResponse> handleBadRequest(HttpRequest<?> req, IllegalArgumentException ex) {
        // Mensagem de negócio é segura de expor ao cliente
        return HttpResponse.badRequest(ErrorResponse.of("INVALID_ARGUMENT", ex.getMessage()));
    }

    @Error(global = true, exception = ConstraintViolationException.class)
    public HttpResponse<ErrorResponse> handleValidation(ConstraintViolationException ex) {
        String mensagem = ex.getConstraintViolations().stream()
            .map(v -> v.getPropertyPath() + ": " + v.getMessage())
            .collect(Collectors.joining(", "));
        return HttpResponse.badRequest(ErrorResponse.of("VALIDATION_ERROR", mensagem));
    }

    @Error(global = true, exception = Exception.class)
    public HttpResponse<ErrorResponse> handleGeneric(HttpRequest<?> req, Exception ex) {
        log.error("Erro interno em {}: {}", req.getPath(), ex.getMessage(), ex); // detalhe no log
        return HttpResponse.serverError(ErrorResponse.of("INTERNAL_ERROR", "Erro interno do servidor"));
    }
}
```

---

### 🔵 P3 — Baixo

---

#### Comentário 21 — `GestaoAluguelVeiculosTest.java`

🔍 **Sugestão de melhoria:** O projeto possui um único teste (`testItWorks()`) que apenas verifica se a aplicação sobe. Não há nenhum teste de unidade para os services (lógica de negócio), nenhum teste de integração para os controllers e nenhuma verificação de regras de domínio como avaliação de pedidos, cálculo de valores ou limite de rendimentos por cliente. A cobertura de testes é efetivamente **0%** das regras de negócio implementadas.

📉 **Impacto/Benefícios da mudança:** Sem testes automatizados, qualquer refatoração é feita às cegas — não há como saber se uma mudança quebrou uma regra de negócio. Testes de unidade dos services documentam o comportamento esperado, servem como rede de segurança para mudanças futuras e forçam um design testável (o que, por si só, melhora a arquitetura, já que serviços com muitas dependências são difíceis de testar em isolamento).

📌 **Sugestão de implementação:**
```java
// PedidoServiceTest.java — exemplos de testes de unidade com mocks:
@ExtendWith(MockitoExtension.class)
class PedidoServiceTest {

    @Mock PedidoRepository pedidoRepository;
    @Mock ClienteRepository clienteRepository;
    @Mock AutomovelRepository automovelRepository;
    @Mock ContratoRepository contratoRepository;
    @Mock AgenteRepository agenteRepository;

    @InjectMocks PedidoService pedidoService;

    @Test
    void deveLancarExcecaoQuandoClienteNaoEncontrado() {
        when(clienteRepository.findByUsuarioId(any())).thenReturn(Optional.empty());
        assertThrows(IllegalArgumentException.class,
            () -> pedidoService.criarPedido(new CreatePedidoRequest(1L, 1L, "2025-01-01", "2025-01-05")));
    }

    @Test
    void deveCalcularValorTotalCorretamente() {
        // automovel com valorDiaria=100.0, período de 3 dias → esperado 300.0
        Automovel automovel = umAutomovelComDiaria(100.0);
        when(automovelRepository.findById(1L)).thenReturn(Optional.of(automovel));
        when(clienteRepository.findByUsuarioId(any())).thenReturn(Optional.of(umCliente()));

        Pedido pedido = pedidoService.criarPedido(new CreatePedidoRequest(1L, 1L, "2025-01-01", "2025-01-04"));

        assertEquals(300.0, pedido.getValorTotal());
    }

    @Test
    void naoDeveAvaliarPedidoJaDecidido() {
        Pedido aprovado = umPedidoComStatus(StatusPedido.APROVADO);
        when(pedidoRepository.findById(1L)).thenReturn(Optional.of(aprovado));

        assertThrows(IllegalArgumentException.class,
            () -> pedidoService.avaliarPedido(1L, 1L, true));
    }
}
```

---

#### Comentário 22 — `AuthController.java:45,54`

🔍 **Sugestão de melhoria:** O `AuthResponse` é construído passando a entidade `Usuario` diretamente no retorno: `new AuthResponse(token, cliente.getUsuario())` (linha 45) e `new AuthResponse(token, userOpt.get())` (linha 54). A entidade `Usuario` contém o campo `senha` — que, mesmo após hashear ainda não deve ser serializada e retornada ao cliente. Isso viola o princípio de **Least Privilege** na resposta da API: retornar apenas o mínimo necessário. Qualquer novo campo sensível adicionado à entidade automaticamente vaza para a resposta da API.

📉 **Impacto/Benefícios da mudança:** Dados expostos na resposta HTTP trafegam pela rede e podem ser interceptados, armazenados em logs do gateway, ou cacheados em proxies. Expor o hash da senha (mesmo bcrypt) é desnecessário e potencialmente explorado em ataques offline. Usar um DTO dedicado `UsuarioDTO` garante controle explícito sobre quais campos são retornados e protege contra vazamentos involuntários ao adicionar novos campos à entidade no futuro.

📌 **Sugestão de implementação:**
```java
// UsuarioDTO.java — DTO seguro para retorno ao cliente
@Serdeable
public record UsuarioDTO(Long id, String nome, String email, String tipoPerfil) {
    public static UsuarioDTO from(Usuario usuario) {
        return new UsuarioDTO(
            usuario.getId(),
            usuario.getNome(),
            usuario.getEmail(),
            usuario.getTipoPerfil().name()
            // campo 'senha' deliberadamente omitido
        );
    }
}

// AuthResponse.java — usar DTO, não entidade:
@Serdeable
public record AuthResponse(String token, UsuarioDTO usuario) {}

// AuthController.java — construir com o DTO:
// Registro:
return HttpResponse.ok(new AuthResponse(token, UsuarioDTO.from(cliente.getUsuario())));

// Login:
return HttpResponse.ok(new AuthResponse(token, UsuarioDTO.from(userOpt.get())));
```

---

## Resumo Final

| Severidade | Qtd | Categorias abordadas |
|-----------|-----|---------------------|
| **P0 Crítico** | 4 | Senhas plaintext, token sem JWT, endpoints abertos, CORS wildcard |
| **P1 Alto** | 6 | DIP, SRP (×2), OCP + Strategy Pattern, God Service, Anemic Domain Model |
| **P2 Médio** | 10 | BigDecimal, DRY, FetchType.EAGER, FK primitiva, Optional, @Transactional, paginação, secrets, Bean Validation, exception handler |
| **P3 Baixo** | 2 | Cobertura de testes, entidade exposta em DTO |
| **Total** | **22** | |

> **Avaliação geral: REQUEST_CHANGES**
> O sistema funciona como prova de conceito, mas possui vulnerabilidades críticas de segurança que impedem uso em produção, e violações sistemáticas de SOLID que comprometem a manutenibilidade. As sugestões P1 de arquitetura (DIP, Strategy Pattern, separação de camadas) têm o maior impacto na qualidade do código a longo prazo.
