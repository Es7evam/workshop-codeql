# Workshop CodeQL


## Pré requisitos:
- Instale o [Visual Studio Code](https://code.visualstudio.com/).
- Instale a [CodeQL extension for Visual Studio Code](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html).
- Você _não_ precisa de instalar o CodeQL para linha de comando. A extensão vai fazer isso por você
- Clone este repositório:
  ```
  git clone --recursive https://github.com/es7evam/workshop-codeql
  ```
  - **Não esqueça do `--recursive`** - Isso te permite clonar as bibliotecas do CodeQL, que foram incluídas como submódulo nesse repositório
  - **E se eu esqueci do `--recursive`** - Se já clonou o repositório sem usar o --recursive, rode:
  ```
  git submodule update --init --remote
  ```
- Clone this repository:
  ```
  git clone --recursive https://github.com/githubuniverseworkshops/codeql
  ```

- Abra o repositório no VSCode: (usando `code .` no terminal ou **File** > **Open Folder** > Abrir a pasta es7evam/workshop-codeql)

- Importe a database (zip neste repositório)
  - Clique no **CodeQL** no canto esquerdo do VSCode
  - Importar de pasta
  - Selecione o Zip


## O Workshop


### Instruções para começar
- Use o autocomplete da sua ide (`Ctrl+Espaço`)
- Para rodar uma query, clique com o botão direito e selecione `Run Query` ou através do comando do VSCode (`Ctrl+Shift+P`)
- Para entender o código e como ele é representado no CodeQL, use o **AST Viewer**. No canto inferior esquerdo da aba da extensão no VScode.
  - Se a AST não aparecer, clique com o botão direito no código e em **View AST**

O resto deste workshop é dividido em diversas partes. Você pode escrever uma query para cada parte ou trabalhar com uma única query que muda a cada parte.

Cada parte tem um **Hint** que descreve classes e predicados úteis nas bibliotecas padrão do CodeQL para C/C++.

Cada parte tem uma **Solução**, que indica uma maneira possível de realizar o desafio. Todas as queries devem começar com `import cpp` para importar as bibliotecas, porém por simplicidade isso foi omitido abaixo em alguns casos.

### Encontrando referências para memória liberada.

1. Encontre todas as chamadsa de função, como `free(x)`, `use(a, b)`, `malloc(r)`
    <details>
    <summary>Hint</summary>
    - Depois que executou a query de exemplo e clicou no resultado, olhe na AST para o código fonte `exemple.cpp`.

    - Uma chamada de função é denotada por `FunctionCall` na biblioteca de C/C++ do CodeQL.

    </details>
     <details>
    <summary>Solução</summary>
    ```ql
    from FunctionCall call
    select call
    ```
    </details>

2. Identifique a `Expr`essão que é usada como primeiro argumento para cada chamada, como `free(<primeiro arg>)` e `use(<primeiro arg>, b)` .
    <details>
    <summary>Hint</summary>

    - Adicione outra variável à sua cláusula `from`. Declare o seu tipo (como por exemplo `Expr`) e dê um nome.

    - Adicione a cláusula `where`

    - O AST viewer e o autocomplete nos ajudam, dizendo que o `FunctionCall` tem um predicado `getArgument(int)` para achar o argumento usando o índice, começando do 0.

    </details>
    <details>
    <summary>Solução</summary>
    ```ql
    from FunctionCall call, Expr arg
    where arg = call.getArgument(0)
    select arg
    ```
    </details>

3. Filtre os seus resultados para mostrar apenas as funções com o nome `free`.
    <details>
    <summary>Hint</summary>

    - `FunctionCall` possui o predicado `getTarget`, que identifica a função(`Function`) sendo chamada.

    - A `Function` (e a maioria dos outros elementos) possui os predicados `getName()` e `hasName(string)` para identificar o seu nome como string.

    - Você também pode se interessar pelo `hasGlobalOrStdName(string)`, que identifica elementos dos namespaces global ou `std`.

    - Use `and` para adicionar condições à sua query.

    - Se você usar `getName()`, use o operador `=` para conferir se dois valores são iguais. Se usar `has..Name(string)` passar o nome como parâmetro já retorna verdadeiro/falso.

    </details><details>
    <summary>Solução</summary>

    ```ql
    from FunctionCall call, Expr arg
    where
      arg = call.getArgument(0) and
      call.getTarget().hasGlobalOrStdName("free")
    select arg
    ```
    </details>


4. (Bônus) Que outras operações podem liberar memória? Tente procurar por `delete` usando o CodeQL (Neste workshop apenas é usada a função `free` :))


5. Coloque a sua lógica em um predicado chamado isSource (`predicate isSource(Expr arg) { ... }`)
    <details>
    <summary>Hint</summary>

    - A keyword `predicado` declara uma relação que não valor de resultado/retorno explícito, mas confere propriedades lógicas sobre as suas variáveis.

    - A cláusula `from` de uma query te permite declarar variáveis, e a cláusula `where` descreve condições para essas variáveis.

      Dentro da definição de um predicado variáveis podem ser declaradas como parâmetro deste ou "localmente", utilizando a keyword `exists`.
      A primeira parte do `exists` declara algumas variáveis e o corpo age como um `where`, garantindo as condições sobre as variáveis.

      ```ql
      exists(<tipo> <nomeVariável> |
        // condições logicas (myvar='x', por exemplo)
      )
      ```

    - Você pode usar o **Quick Evalutation** para testar o predicado por si só.
    </details>
    <details>
    <summary>Solução</summary>

    ```ql
    predicate isSource(Expr arg) {
      exists(FunctionCall call |
        arg = call.getArgument(0) and
        call.getTarget().hasGlobalOrStdName("free")
      )
    }
    ```
    </details>


6. Agora vamos modificar a query para analisar o fluxo da informação do ponteiro que foi liberado. Para isso utilizaremos a library para **data flow analysis**, que nos ajuda a responder perguntas como: Essa expressão já teve um valor que originou de algum outro lugar em particular do programa?

    Nós podemos visualizar o problema de fluxo de dados como um de encontrar caminhos por um grafo direcionado, onde os nós (**nodes**) de um grafo são lugares que um código fonte pode ter um valor, e as arestas (**edges**) representam o fluxo de dados dentre estes elementos. Se um caminho existe, então existe fluxo de dados entre os dois nós.

    A classe `DataFlow::Node` descreve todos os nós de fluxo. Estes são diferentes dos nós da AST, que só podem representar a estrutura do código fonte. O `DataFlow::Node` tem diversas subclasses que descrevem diferentes tipos de nós, dependendo do tipo da sintaxe do programa que eles representam.

    Você pode descobrir mais na [documentação](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp).

    Modifique o seu predicado para descrever `arg` como um `DataFlow::Node`, não um `Expr`.

    <details><summary>Instructions</summary>

    - Adicione `import semmle.code.cpp.dataflow.DataFlow` ao seu arquivo da query.

    - Mude o seu predicado para que o parâmetro seja do tipo `DataFlow::Node`

    - Isso vai te dar um erro de compilação, dado que os tipos não batem mais. Converta o nó para o tipo `Expr` utilizando o predicado `asExpr()`.

    </details><details>
    <summary>Solução</summary>

    ```ql
    import semmle.code.cpp.dataflow.DataFlow

    predicate isSource(DataFlow::Node arg) {
      exists(FunctionCall call |
        arg.asExpr() = call.getArgument(0) and
        call.getTarget().hasGlobalOrStdName("free")
      )
    }
    ```
    </details>

7. Vamos pensar sobre o significado da função `free` e o valor do seu argumento.
    _Antes_ da função ser executada, o argumento é um ponteiro para uma memória, e é passado para a função como referência.

    _After_ the function body, the memory that was referenced by the pointer has been freed.
    _Depois_ da chamada da função, a memória que foi referenciada pelo ponteiro foi liberada.

    Então a _única_ expressão para o argumento da chamada na sintaxe do programa na verdade possui _dois_ valores possíveis a serem pensados no _data flow graph_:
    1. O ponteiro depois de ser liberado
    2. O ponteiro após ser liberado.

    Clica na Hint para visualizar como distinguir entre esses dois casos. Modifique o seu predicado para que `arg` descreva a memória _após_ ser liberada, não antes.

    <details><summary>Hint</summary>

    - O valor antes da chamada é um `DataFlow::ExprNode`, um subtipo de `DataFlow::Node`
    - Nós podemos chamar `asExpr()` sobre tal nó para obter a expressão sintática original.

    - O valor após a chamada é um `DataFlow::DefinitionByReferenceNode`.
    - Nós podemos chamar `asDefiningArgument()` nesse nó para obter a sintaxe da expressão original.

    - Vá até a definição de `DataFlow::Node` para ler mais

    - Modifique o seu predicado para descrever `arg` utilizando `getDefiningArgument()`.

    </details><details>
    <summary>Solução</summary>

    ```ql
    predicate isSource(DataFlow::Node arg) {
      exists(FunctionCall call |
        arg.asDefiningArgument() = call.getArgument(0) and
        call.getTarget().hasGlobalOrStdName("free")
      )
    }
    ```
    </details>

### Encontrando dereferences <a id="section2"></a>

Um dereference é um local no programa que utiliza a memória referenciada por um ponteiro.

1. Escreva o `predicate isSink(DataFlow::Node sink)` que descreve expressões que podem ser dereferenciadas.
    <details>
    <summary>Hint</summary>

      - Pense sobre algumas operações que podem dereferenciar um ponteiro. O operador `*`? Passar para uma função? Aritmética de ponteiros? Utilize o visualizador da AST para explorer como estas operações são modeladas no CodeQL.
      - Procure por `dereference` no autocomplete para encontrar um predicado da biblioteca padrão que modela todos estes padrões por você.
    </details>
    <details>
    <summary>Solução</summary>

    ```ql
    predicate isSink(DataFlow::Node sink) {
      dereferenced(sink.asExpr())
    }
    ```
    </details>

### Encontrando vulnerabilidades use-after-free <a id="section3"></a>

Nós agora identificamos (a) locais no programa que referenciam memória liberada e (b) locais no programa que dereferenciam um ponteiro para a memória. Agora queremos juntar os dois e perguntar: um ponteiro para a memória pode ter um _fluxo_ para uma potencialmente insegura operação de dereferenciação?

Este é o problema de fluxo de dados. Nós podemos enfrentá-lo utilizando **local data flow analysis**, que o escopo está limitado a uma única função. Porém, é possível que as operações `free` e `deref` estejam em funções diferentes. Nós chamamos isso de um  problema de **global data flow**, e utilizamos as bibliotecas do CodeQL para esse propósito.

Nessa seção criaremos uma query do tipo **path-problem**, capaz de olhar no fluxo de dados global, ao popular este template no início da query:

```ql
/**
 * @name Use after free
 * @kind path-problem
 * @id cpp/workshop/use-after-free
 */
import cpp
import semmle.code.cpp.dataflow.DataFlow
import DataFlow::PathGraph

class Config extends DataFlow::Configuration {
  Config() { this = "Config: nome não importa" }

  /* TODO mova a solução da seção 1 */
  override predicate isSource(DataFlow::Node source) {
    exists(/* TODO preencha com a seção 1 */ |
      /* TODO preencha com a seção 1 */
    )
  }

  /* TODO mova a solução da seção 2 */
  override predicate isSink(DataFlow::Node sink) {
    /* TODO preencha com a seção 2 **/
  }
}

from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Memory is $@ and $@, causing a potential vulnerability.", source, "freed here", sink, "used here"
```

1. Preencha ou mova o predicado `isSource` escrito na [Seção 1](#section1).

1. Preencha ou mova o predicado `isSink` escrito na [Seção 2](#section2).

1. Você agora pode executar a query completa. Utilize o path explorer nos resultados para visualizar o que foi obtido

    <details>
    <summary>Query Completa</summary>

      ```ql
      /**
       * @name Use after free
       * @kind path-problem
       * @id cpp/workshop/use-after-free
       */
      import cpp
      import semmle.code.cpp.dataflow.DataFlow
      import DataFlow::PathGraph

      class Config extends DataFlow::Configuration {
        Config() { this = "Config: name doesn't matter" }
        override predicate isSource(DataFlow::Node source) {
          exists(FunctionCall call |
            source.asDefiningArgument() = call.getArgument(0) and
            call.getTarget().hasGlobalOrStdName("free")
          )
        }
        override predicate isSink(DataFlow::Node sink) {
          dereferenced(sink.asExpr())
        }
      }

      from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
      where config.hasFlowPath(source, sink)
      select sink, source, sink, "Memory is $@ and $@, causing a potential vulnerability.", source, "freed here", sink, "used here"
      ```
    </details>


## Referências

Este workshop (especialmente o README) foi fortemente baseado no [cpp-codeql-workshop](https://github.com/githubuniverseworkshops/codeql/)