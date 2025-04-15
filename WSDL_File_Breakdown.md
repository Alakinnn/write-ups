## WSDL File Breakdown

---

Let us now go over the identified WSDL file above together.

The above WSDL file follows the [WSDL version 1.1](https://www.w3.org/TR/2001/NOTE-wsdl-20010315) layout and consists of the following elements.

- `Definition`
    - The root element of all WSDL files. Inside the definition, the name of the web service is specified, all namespaces used across the WSDL document are declared, and all other service elements are defined.
    - Code: xml
        
        ```xml
        <wsdl:definitions targetNamespace="http://tempuri.org/" 
        
            <wsdl:types></wsdl:types>
            <wsdl:message name="LoginSoapIn"></wsdl:message>
            <wsdl:portType name="HacktheBoxSoapPort">
          	  <wsdl:operation name="Login"></wsdl:operation>
            </wsdl:portType>
            <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
          	  <wsdl:operation name="Login">
          		  <soap:operation soapAction="Login" style="document"/>
          		  <wsdl:input></wsdl:input>
          		  <wsdl:output></wsdl:output>
          	  </wsdl:operation>
            </wsdl:binding>
            <wsdl:service name="HacktheboxService"></wsdl:service>
        </wsdl:definitions>
        ```
        
- `Data Types`
    - The data types to be used in the exchanged messages.
    - Code: xml
        
        ```xml
        <wsdl:types>
            <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
          	  <s:element name="LoginRequest">
          		  <s:complexType>
          			  <s:sequence>
          				  <s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
          				  <s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
          			  </s:sequence>
          		  </s:complexType>
          	  </s:element>
          	  <s:element name="LoginResponse">
          		  <s:complexType>
          			  <s:sequence>
          				  <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
          			  </s:sequence>
          		  </s:complexType>
          	  </s:element>
          	  <s:element name="ExecuteCommandRequest">
          		  <s:complexType>
          			  <s:sequence>
          				  <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
          			  </s:sequence>
          		  </s:complexType>
          	  </s:element>
          	  <s:element name="ExecuteCommandResponse">
          		  <s:complexType>
          			  <s:sequence>
          				  <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
          			  </s:sequence>
          		  </s:complexType>
          	  </s:element>
            </s:schema>
        </wsdl:types>
        ```
        
- `Messages`
    - Defines input and output operations that the web service supports. In other words, through the _messages_ element, the messages to be exchanged, are defined and presented either as an entire document or as arguments to be mapped to a method invocation.
    - Code: xml
        
        ```xml
        <!-- Login Messages -->
        <wsdl:message name="LoginSoapIn">
            <wsdl:part name="parameters" element="tns:LoginRequest"/>
        </wsdl:message>
        <wsdl:message name="LoginSoapOut">
            <wsdl:part name="parameters" element="tns:LoginResponse"/>
        </wsdl:message>
        <!-- ExecuteCommand Messages -->
        <wsdl:message name="ExecuteCommandSoapIn">
            <wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
        </wsdl:message>
        <wsdl:message name="ExecuteCommandSoapOut">
            <wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
        </wsdl:message>
        ```
        
- `Operation`
    - Defines the available SOAP actions alongside the encoding of each message.
- `Port Type`
    - Encapsulates every possible input and output message into an operation. More specifically, it defines the web service, the available operations and the exchanged messages. Please note that in WSDL version 2.0, the _interface_ element is tasked with defining the available operations and when it comes to messages the (data) types element handles defining them.
    - Code: xml
        
        ```xml
        <wsdl:portType name="HacktheBoxSoapPort">
            <!-- Login Operaion | PORT -->
            <wsdl:operation name="Login">
          	  <wsdl:input message="tns:LoginSoapIn"/>
          	  <wsdl:output message="tns:LoginSoapOut"/>
            </wsdl:operation>
            <!-- ExecuteCommand Operation | PORT -->
            <wsdl:operation name="ExecuteCommand">
          	  <wsdl:input message="tns:ExecuteCommandSoapIn"/>
          	  <wsdl:output message="tns:ExecuteCommandSoapOut"/>
            </wsdl:operation>
        </wsdl:portType>
        ```
        
- `Binding`
    - Binds the operation to a particular port type. Think of bindings as interfaces. A client will call the relevant port type and, using the details provided by the binding, will be able to access the operations bound to this port type. In other words, bindings provide web service access details, such as the message format, operations, messages, and interfaces (in the case of WSDL version 2.0).
    - Code: xml
        
        ```xml
        <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
            <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
            <!-- SOAP Login Action -->
            <wsdl:operation name="Login">
          	  <soap:operation soapAction="Login" style="document"/>
          	  <wsdl:input>
          		  <soap:body use="literal"/>
          	  </wsdl:input>
          	  <wsdl:output>
          		  <soap:body use="literal"/>
          	  </wsdl:output>
            </wsdl:operation>
            <!-- SOAP ExecuteCommand Action -->
            <wsdl:operation name="ExecuteCommand">
          	  <soap:operation soapAction="ExecuteCommand" style="document"/>
          	  <wsdl:input>
          		  <soap:body use="literal"/>
          	  </wsdl:input>
          	  <wsdl:output>
          		  <soap:body use="literal"/>
          	  </wsdl:output>
            </wsdl:operation>
        </wsdl:binding>
        ```
        
- `Service`
    - A client makes a call to the web service through the name of the service specified in the service tag. Through this element, the client identifies the location of the web service.
    - Code: xml
        
        ```xml
            <wsdl:service name="HacktheboxService">
        
              <wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
                <soap:address location="http://localhost:80/wsdl"/>
              </wsdl:port>
        
            </wsdl:service>
        ```
        

In the `SOAP Action Spoofing` section, later on, we will see how we can leverage the identified WSDL file to interact with the web service.