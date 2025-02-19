package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// ---------------------
// Tipos y Variables Globales
// ---------------------

// DomainResult representa el resultado de la verificación de un dominio.
type DomainResult struct {
	Domain      string   `json:"domain"`
	Available   bool     `json:"available"`
	WhoisData   string   `json:"whois_data"`
	DNSResolved bool     `json:"dns_resolved"`
	Suggestions []string `json:"suggestions,omitempty"`
	Error       string   `json:"error,omitempty"`
}

var (
	// Cache en memoria para almacenar resultados y evitar consultas repetidas.
	cache      = make(map[string]DomainResult)
	cacheMutex sync.RWMutex

	// Configuración global (modificable vía flags)
	numWorkers   int           = 5
	queryTimeout time.Duration = 10 * time.Second
	rateLimitDur time.Duration = 500 * time.Millisecond // 1 consulta cada 500 ms

	// Logger con Logrus
	logger = logrus.New()

	// Archivo para persistir resultados
	resultFile = "results.json"
)

// Registradores simulados (URLs de búsqueda concatenando el dominio)
var registrars = []struct {
	Name string
	URL  string
}{
	{"Namecheap", "https://www.namecheap.com/domains/registration/results/?domain="},
	{"GoDaddy", "https://www.godaddy.com/domainsearch/find?checkAvail=1&tmskey=&domainToCheck="},
	{"Hostinger", "https://www.hostinger.com/domain-checker?domain="},
	{"Cloudflare", "https://www.cloudflare.com/registrar/"},
}

// ---------------------
// Funciones de Dominio
// ---------------------

// processDomain realiza la verificación del dominio usando WHOIS, chequeo DNS y sugiere alternativas si es necesario.
func processDomain(ctx context.Context, domain string) DomainResult {
	// Revisa si ya existe en caché
	cacheMutex.RLock()
	if cached, found := cache[domain]; found {
		cacheMutex.RUnlock()
		logger.Debugf("Resultado en cache para: %s", domain)
		return cached
	}
	cacheMutex.RUnlock()

	var result DomainResult
	result.Domain = domain

	// Canal para recibir la respuesta de WHOIS.
	whoisCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Ejecuta la consulta WHOIS en goroutine para poder cancelar si se excede el timeout.
	go func() {
		data, err := whois.Whois(domain)
		if err != nil {
			errCh <- err
			return
		}
		whoisCh <- data
	}()

	// Espera la respuesta o el timeout.
	select {
	case <-ctx.Done():
		result.Error = "Timeout en consulta WHOIS"
		result.Available = false
	case err := <-errCh:
		result.Error = err.Error()
		result.Available = false
	case data := <-whoisCh:
		result.WhoisData = data
		result.Available = analyzeWhoisData(data)
	}

	// Chequeo adicional: verificación DNS
	if _, err := net.LookupHost(domain); err == nil {
		result.DNSResolved = true
	} else {
		result.DNSResolved = false
	}

	// Si el dominio no está disponible, sugiere alternativas.
	if !result.Available {
		result.Suggestions = generateDomainSuggestions(domain)
	}

	// Almacena en caché el resultado.
	cacheMutex.Lock()
	cache[domain] = result
	cacheMutex.Unlock()

	return result
}

// analyzeWhoisData utiliza heurísticas simples para determinar si el dominio podría estar libre.
func analyzeWhoisData(data string) bool {
	lower := strings.ToLower(data)
	indicators := []string{
		"no match for",
		"not found",
		"no data found",
		"status: free",
		"no existe",
	}
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	// Si no se detecta ningún indicador, se asume que el dominio está ocupado.
	return false
}

// generateDomainSuggestions crea algunas alternativas simples para un dominio ocupado.
func generateDomainSuggestions(domain string) []string {
	suggestions := []string{}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return suggestions
	}
	base := parts[0]
	tld := parts[1]

	// Sugerencias simples: cambiar TLD o agregar números.
	suggestions = append(suggestions, fmt.Sprintf("%s.net", base))
	suggestions = append(suggestions, fmt.Sprintf("%s.org", base))
	suggestions = append(suggestions, fmt.Sprintf("%s123.%s", base, tld))
	return suggestions
}

// sendNotification simula el envío de una notificación (por email, SMS, Slack, etc.)
func sendNotification(result DomainResult) {
	// Aquí se integraría la lógica real de notificación.
	logger.Infof("Notificación: El dominio '%s' está DISPONIBLE. Revisar en los registradores.", result.Domain)
	// Ejemplo: enviar email o mensaje a un bot.
}

// ---------------------
// Worker Pool y Rate Limiting
// ---------------------

// worker es la función que procesará dominios recibidos desde el canal jobs y enviará los resultados a results.
func worker(id int, jobs <-chan string, results chan<- DomainResult, rateLimiter <-chan time.Time, timeout time.Duration) {
	for domain := range jobs {
		// Espera según el rate limiter
		<-rateLimiter

		logger.Debugf("[Worker %d] Procesando %s", id, domain)
		// Crea un contexto con timeout para la consulta.
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		result := processDomain(ctx, domain)
		cancel()

		results <- result
	}
}

// ---------------------
// Persistencia: Guardar Resultados en JSON
// ---------------------

func persistResults(results []DomainResult) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		logger.Errorf("Error al convertir resultados a JSON: %v", err)
		return
	}
	if err := ioutil.WriteFile(resultFile, data, 0644); err != nil {
		logger.Errorf("Error al escribir el archivo %s: %v", resultFile, err)
	} else {
		logger.Infof("Resultados guardados en %s", resultFile)
	}
}

// ---------------------
// CLI con Cobra
// ---------------------

var rootCmd = &cobra.Command{
	Use:   "domcheck",
	Short: "domcheck es una herramienta para verificar la disponibilidad de dominios",
	Long:  "Una aplicación que verifica dominios usando WHOIS, DNS y ofrece sugerencias, con soporte de CLI y una interfaz web.",
}

// checkCmd procesa uno o varios dominios vía línea de comandos o desde un archivo.
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Verifica la disponibilidad de uno o varios dominios",
	Run: func(cmd *cobra.Command, args []string) {
		// Recoge flags
		domainFlag, _ := cmd.Flags().GetString("domain")
		fileFlag, _ := cmd.Flags().GetString("file")
		workers, _ := cmd.Flags().GetInt("workers")
		timeoutSec, _ := cmd.Flags().GetInt("timeout")

		if domainFlag == "" && fileFlag == "" {
			fmt.Println("Debe proporcionar un dominio con --domain o un archivo con --file")
			return
		}

		// Actualiza configuración global
		numWorkers = workers
		queryTimeout = time.Duration(timeoutSec) * time.Second

		// Crea la lista de dominios
		var domains []string
		if fileFlag != "" {
			data, err := ioutil.ReadFile(fileFlag)
			if err != nil {
				logger.Fatalf("Error al leer el archivo: %v", err)
			}
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				d := strings.TrimSpace(line)
				if d != "" {
					domains = append(domains, d)
				}
			}
		}
		if domainFlag != "" {
			domains = append(domains, strings.TrimSpace(domainFlag))
		}

		// Canales para la comunicación entre el productor y los workers.
		jobChan := make(chan string, len(domains))
		resultChan := make(chan DomainResult, len(domains))
		// Rate limiter: ticker que emite cada rateLimitDur.
		limiter := time.Tick(rateLimitDur)

		// Inicia los workers.
		var wg sync.WaitGroup
		for i := 1; i <= numWorkers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				worker(id, jobChan, resultChan, limiter, queryTimeout)
			}(i)
		}

		// Envía los dominios al canal de trabajo.
		for _, d := range domains {
			jobChan <- d
		}
		close(jobChan)

		// Espera a que todos los workers terminen.
		wg.Wait()
		close(resultChan)

		// Recopila y muestra los resultados.
		var allResults []DomainResult
		for res := range resultChan {
			allResults = append(allResults, res)
			// Salida en consola con colores.
			if res.Available {
				color.Green("El dominio %s está DISPONIBLE.", res.Domain)
				fmt.Println("Registradores:")
				for _, reg := range registrars {
					fmt.Printf("  - %s: %s%s\n", reg.Name, reg.URL, res.Domain)
				}
				// Envía notificación
				sendNotification(res)
			} else {
				color.Red("El dominio %s está OCUPADO.", res.Domain)
				if len(res.Suggestions) > 0 {
					fmt.Println("Sugerencias:")
					for _, s := range res.Suggestions {
						fmt.Printf("  - %s\n", s)
					}
				}
			}
			fmt.Println("--------------------------------------------------")
		}

		// Persiste los resultados en un archivo JSON.
		persistResults(allResults)
	},
}

// webCmd inicia un servidor web para consultas en tiempo real.
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Inicia la interfaz web para verificar dominios",
	Run: func(cmd *cobra.Command, args []string) {
		// Configura Gin
		router := gin.Default()
		router.GET("/check", func(c *gin.Context) {
			domain := c.Query("domain")
			if domain == "" {
				c.JSON(400, gin.H{"error": "Parámetro 'domain' es requerido"})
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()
			result := processDomain(ctx, domain)
			c.JSON(200, result)
		})
		// Ruta de ejemplo para la página principal
		router.GET("/", func(c *gin.Context) {
			c.Header("Content-Type", "text/html")
			c.String(200, `<html>
	<head><title>Domain Checker</title></head>
	<body>
	  <h1>Verifica un dominio</h1>
	  <form action="/check" method="get">
	    <input type="text" name="domain" placeholder="ejemplo.com"/>
	    <button type="submit">Verificar</button>
	  </form>
	</body>
</html>`)
		})
		// Inicia el servidor en el puerto 8080
		logger.Infof("Iniciando servidor web en http://localhost:8080")
		router.Run(":8080")
	},
}

// ---------------------
// Función main y Setup de Cobra
// ---------------------

func init() {
	// Configura niveles de log (debug/info)
	logger.SetLevel(logrus.DebugLevel)

	// Flags para el comando "check"
	checkCmd.Flags().String("domain", "", "Dominio a verificar (ejemplo: example.com)")
	checkCmd.Flags().String("file", "", "Archivo de texto con lista de dominios (uno por línea)")
	checkCmd.Flags().Int("workers", 5, "Número de workers concurrentes")
	checkCmd.Flags().Int("timeout", 10, "Timeout (en segundos) para cada consulta WHOIS")

	// Agrega los comandos a la raíz
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(webCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Error ejecutando el comando: %v", err)
		os.Exit(1)
	}
}
