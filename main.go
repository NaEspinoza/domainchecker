package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/likexian/whois"
)

// Registrar representa un registrador con su nombre y URL base para búsqueda.
type Registrar struct {
	Name string
	URL  string
}

// Lista de registradores con URL de búsqueda (se concatenará el dominio al final).
var registrars = []Registrar{
	{"Namecheap", "https://www.namecheap.com/domains/registration/results/?domain="},
	{"GoDaddy", "https://www.godaddy.com/domainsearch/find?checkAvail=1&tmskey=&domainToCheck="},
	{"Hostinger", "https://www.hostinger.com/domain-checker?domain="},
	{"Cloudflare", "https://www.cloudflare.com/registrar/"},
}

func main() {
	// Definimos los flags: -domain para un dominio y -file para un archivo con dominios.
	domainFlag := flag.String("domain", "", "Dominio a verificar (ejemplo: example.com)")
	fileFlag := flag.String("file", "", "Archivo de texto con lista de dominios (uno por línea)")
	flag.Parse()

	if *domainFlag == "" && *fileFlag == "" {
		fmt.Println("Debe proporcionar un dominio con -domain o un archivo con -file")
		os.Exit(1)
	}

	// Se crea la lista de dominios a procesar.
	var domains []string
	if *fileFlag != "" {
		f, err := os.Open(*fileFlag)
		if err != nil {
			log.Fatalf("Error al abrir el archivo: %v", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			dom := strings.TrimSpace(scanner.Text())
			if dom != "" {
				domains = append(domains, dom)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error al leer el archivo: %v", err)
		}
	}
	if *domainFlag != "" {
		domains = append(domains, strings.TrimSpace(*domainFlag))
	}

	// Se utiliza un WaitGroup para procesar dominios en paralelo.
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			available, err := checkDomainAvailability(dom)
			if err != nil {
				fmt.Printf("Error verificando %s: %v\n", dom, err)
				return
			}
			if available {
				fmt.Printf("El dominio %s está DISPONIBLE.\n", dom)
				fmt.Println("Puedes comprarlo en:")
				for _, reg := range registrars {
					fmt.Printf(" - %s: %s%s\n", reg.Name, reg.URL, dom)
				}
			} else {
				fmt.Printf("El dominio %s está OCUPADO.\n", dom)
			}
			fmt.Println("--------------------------------------------------")
		}(domain)
	}
	wg.Wait()
}

// checkDomainAvailability realiza una consulta WHOIS al dominio y busca ciertos indicadores en la respuesta
// que puedan sugerir que el dominio no está registrado.
func checkDomainAvailability(domain string) (bool, error) {
	// Realizamos la consulta WHOIS.
	result, err := whois.Whois(domain)
	if err != nil {
		return false, err
	}

	// Convertimos la respuesta a minúsculas para facilitar la búsqueda de palabras clave.
	lowerResult := strings.ToLower(result)
	// Indicadores comunes que sugieren que el dominio está libre.
	indicators := []string{
		"no match for",
		"not found",
		"no data found",
		"status: free",
		"no existe",
	}

	for _, indicator := range indicators {
		if strings.Contains(lowerResult, indicator) {
			return true, nil
		}
	}

	// Si no se encuentran indicadores, asumimos que el dominio está ocupado.
	return false, nil
}
