# Logstash:     

### **a. Install Ruby environment**

1. Go to [JRuby download location](https://rubyinstaller.org/downloads/)

1. Install from file

    ```bash
    gem install bundle
    ```
2. Add jruby /bin folder to your PATH variable

### **b. Install Logstash**

1. [Install Logstash](https://www.elastic.co/guide/en/logstash/current/installing-logstash.html)

2. Add Logstash /bin folder to your PATH variable

### **c. Use plugin**

1. Build the custom plugin  

    ```bash
    gem build logstash-output-bcdb
    ```

2. Install custom plugin to logstash  

    ```bash
    logstash-plugin install logstash-output-bcdb-0.0.1.gem
    ```

3. Verify installed gem plugins
    ```bash
    gem list
    ```

4. Configure logstash using logstash.conf:

    ```bash
    output {
        bcdb {
          base_url => "http://<bcdb-url>:32018/services/core/v1/api"
          auth_url => "http://<bcdb-url>:32018/services/oauth/token"
          bcdb_entity => "entity_name"
          username => "user"
          password => "pass"
          client_id => "0x01"
          client_secret => "0x000001"
          retryable_codes => [499]
          format => "json_batch"
        }
    ```
5. Execute logstash based on logstash.conf 

    ```bash
    logstash -f <absolute-path-to>/logstash.conf
    ```