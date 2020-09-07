
EXEC=fim_db
SCHEMA=schema.o

$(EXEC): main.o $(EXEC).o sqlite3.o $(SCHEMA) dependencies.o
	@gcc -o $(EXEC) $^ -pthread -lcrypto -ldl -g -ggdb -O2

%.o: %.c
	@gcc -c -o $@ $^ -I./ -g -DCOMMIT_INTERVAL=1

$(SCHEMA): schema_fim_db.sql
	@echo 'const char *schema_fim_sql = "'"`cat $< | tr -d \"\n\"`"'";' | gcc -xc -c -o $@ -

clean:
	@rm -f ./*.o $(EXEC)
