package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"
	
	"github.com/p0rt/p0rt/internal/metrics"
)

// ReservationManagerInterface defines the interface for domain reservations
type ReservationManagerInterface interface {
	IsReserved(domain string) (bool, string)
	GetReservedDomain(fingerprint string) (string, bool)
	AddReservation(domain, fingerprint, comment string) error
	RemoveReservation(domain string) error
	RemoveReservationByFingerprint(fingerprint string) error
	ListReservations() []Reservation
	GetStats() map[string]interface{}
}

type Generator struct {
	words              []string
	store              Store
	reservationManager ReservationManagerInterface
}

func NewGenerator(config storageConfig) (*Generator, error) {
	store, err := NewStore(config)
	if err != nil {
		return nil, err
	}

	return &Generator{
		words: wordsList,
		store: store,
	}, nil
}

// NewGeneratorWithReservations creates a generator with reservation support
func NewGeneratorWithReservations(config storageConfig, reservationManager ReservationManagerInterface) (*Generator, error) {
	store, err := NewStore(config)
	if err != nil {
		return nil, err
	}

	return &Generator{
		words:              wordsList,
		store:              store,
		reservationManager: reservationManager,
	}, nil
}

// GetReservationManager returns the reservation manager
func (g *Generator) GetReservationManager() ReservationManagerInterface {
	return g.reservationManager
}

// NewGeneratorWithDataDir creates a generator with JSON storage (backwards compatibility)
func NewGeneratorWithDataDir(dataDir string) (*Generator, error) {
	return NewGenerator(storageConfig{
		Type:    "json",
		DataDir: dataDir,
	})
}

// NewGeneratorFromConfig creates a generator from config package type
func NewGeneratorFromConfig(configType, dataDir, redisURL, redisPassword string, redisDB int) (*Generator, error) {
	// Create reservation manager based on storage type
	var reservationManager ReservationManagerInterface
	var err error

	switch configType {
	case "redis":
		reservationManager, err = NewRedisReservationManager(redisURL, redisPassword, redisDB)
	case "json", "":
		reservationManager, err = NewReservationManager(dataDir)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", configType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create reservation manager: %w", err)
	}

	return NewGeneratorWithReservations(storageConfig{
		Type:          configType,
		DataDir:       dataDir,
		RedisURL:      redisURL,
		RedisPassword: redisPassword,
		RedisDB:       redisDB,
	}, reservationManager)
}

func (g *Generator) Generate(key string) string {
	return g.GenerateWithFingerprint(key, "")
}

// GenerateWithFingerprint generates a domain for an SSH key with optional fingerprint for reservations
func (g *Generator) GenerateWithFingerprint(key, fingerprint string) string {
	// Calculate SSH key hash
	hash := sha256.Sum256([]byte(key))
	keyHash := hex.EncodeToString(hash[:])

	// Check for reserved domain if reservation manager is available and fingerprint is provided
	if g.reservationManager != nil && fingerprint != "" {
		if reservedDomain, exists := g.reservationManager.GetReservedDomain(fingerprint); exists {
			// Update last seen time in storage
			g.store.SetDomain(keyHash, reservedDomain)
			return reservedDomain
		}
	}

	// Check if we already have a domain for this key
	if domain, exists := g.store.GetDomain(keyHash); exists {
		// Update last seen time
		g.store.SetDomain(keyHash, domain)
		return domain
	}

	// Generate new domain
	domain := g.generateNewDomain(keyHash)

	// Check for collisions and reservations
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		// Check if domain is taken in storage
		if taken, _ := g.store.IsDomainTaken(domain); taken {
			domain = g.generateNewDomainWithSalt(keyHash, i)
			continue
		}

		// Check if domain is reserved (if reservation manager is available)
		if g.reservationManager != nil {
			if reserved, reservedFingerprint := g.reservationManager.IsReserved(domain); reserved {
				// Domain is reserved for another key, generate a different one
				if fingerprint == "" || reservedFingerprint != fingerprint {
					domain = g.generateNewDomainWithSalt(keyHash, i)
					continue
				}
				// Domain is reserved for this key, we can use it
			}
		}

		// Domain is available, store it and return
		g.store.SetDomain(keyHash, domain)
		
		// Record domain generation metric
		metrics.RecordDomainGenerated()
		
		return domain
	}

	// Fallback: use random domain if all attempts fail
	domain = g.GenerateRandom()
	g.store.SetDomain(keyHash, domain)
	
	// Record domain generation metric
	metrics.RecordDomainGenerated()
	
	return domain
}

func (g *Generator) generateNewDomain(keyHash string) string {
	hashInt := new(big.Int)
	hashInt.SetString(keyHash, 16)

	wordsCount := big.NewInt(int64(len(g.words)))

	// Generate three words by using different parts of the hash
	word1Index := new(big.Int)
	word1Index.Mod(hashInt, wordsCount)

	// Shift hash for second word
	hashInt.Rsh(hashInt, 8)
	word2Index := new(big.Int)
	word2Index.Mod(hashInt, wordsCount)

	// Shift hash for third word
	hashInt.Rsh(hashInt, 8)
	word3Index := new(big.Int)
	word3Index.Mod(hashInt, wordsCount)

	word1 := g.words[word1Index.Int64()]
	word2 := g.words[word2Index.Int64()]
	word3 := g.words[word3Index.Int64()]

	return word1 + "-" + word2 + "-" + word3
}

func (g *Generator) generateNewDomainWithSalt(keyHash string, salt int) string {
	// Add salt to hash to generate different domain
	saltedHash := sha256.Sum256([]byte(keyHash + fmt.Sprintf("%d", salt)))
	return g.generateNewDomain(hex.EncodeToString(saltedHash[:]))
}

func (g *Generator) GenerateRandom() string {
	rand.Seed(time.Now().UnixNano())
	word1 := g.words[rand.Intn(len(g.words))]
	word2 := g.words[rand.Intn(len(g.words))]
	word3 := g.words[rand.Intn(len(g.words))]
	return word1 + "-" + word2 + "-" + word3
}

// GetStats returns domain storage statistics
func (g *Generator) GetStats() map[string]interface{} {
	return g.store.GetStats()
}

// CleanupOldDomains removes domains not used in the specified duration
func (g *Generator) CleanupOldDomains(maxAge time.Duration) int {
	return g.store.Cleanup(maxAge)
}

var wordsList = []string{
	"aardvark", "albatross", "alligator", "alpaca", "ant", "anteater", "antelope", "ape",
	"armadillo", "baboon", "badger", "barracuda", "bat", "bear", "beaver", "bee",
	"beetle", "bison", "boar", "bobcat", "buffalo", "butterfly", "camel", "capybara",
	"caribou", "cat", "caterpillar", "cheetah", "chicken", "chimpanzee", "chinchilla", "chipmunk",
	"clam", "cobra", "cockroach", "cod", "condor", "coral", "cougar", "cow",
	"coyote", "crab", "crane", "crocodile", "crow", "deer", "dingo", "dinosaur",
	"dog", "dolphin", "donkey", "dove", "dragon", "dragonfly", "duck", "eagle",
	"eel", "elephant", "elk", "emu", "falcon", "ferret", "finch", "fish",
	"flamingo", "fly", "fox", "frog", "gazelle", "gecko", "gerbil", "giraffe",
	"goat", "goose", "gopher", "gorilla", "grasshopper", "grouse", "hamster", "hare",
	"hawk", "hedgehog", "heron", "herring", "hippopotamus", "hornet", "horse", "hummingbird",
	"hyena", "ibex", "iguana", "impala", "jackal", "jaguar", "jay", "jellyfish",
	"kangaroo", "koala", "kookaburra", "ladybug", "lark", "lemur", "leopard", "lion",
	"llama", "lobster", "locust", "loris", "louse", "lynx", "macaw", "mackerel",
	"magpie", "mallard", "manatee", "mandrill", "mantis", "marten", "meerkat", "mink",
	"mole", "mongoose", "monkey", "moose", "mosquito", "moth", "mouse", "mule",
	"narwhal", "newt", "nightingale", "ocelot", "octopus", "okapi", "opossum", "orangutan",
	"oryx", "ostrich", "otter", "owl", "ox", "oyster", "panda", "panther",
	"parrot", "partridge", "peacock", "pelican", "penguin", "pheasant", "pig", "pigeon",
	"pony", "porcupine", "porpoise", "puffin", "puma", "quail", "quokka", "rabbit",
	"raccoon", "ram", "rat", "raven", "reindeer", "rhinoceros", "robin", "rooster",
	"salamander", "salmon", "sandpiper", "sardine", "scorpion", "seahorse", "seal", "shark",
	"sheep", "shrew", "shrimp", "skunk", "sloth", "slug", "snail", "snake",
	"sparrow", "spider", "squid", "squirrel", "starfish", "starling", "stingray", "stork",
	"swallow", "swan", "tapir", "termite", "tiger", "toad", "toucan", "trout",
	"turkey", "turtle", "viper", "vulture", "wallaby", "walrus", "wasp", "weasel",
	"whale", "wolf", "wolverine", "wombat", "woodpecker", "worm", "yak", "zebra",
	"airplane", "alarm", "anchor", "apple", "apron", "arrow", "axe", "backpack",
	"badge", "bag", "ball", "balloon", "banana", "bandana", "barrel", "basket",
	"battery", "beach", "bean", "bed", "bell", "bench", "bicycle", "binoculars",
	"blanket", "blender", "boat", "bolt", "bomb", "book", "boot", "bottle",
	"bow", "bowl", "box", "bracelet", "brain", "bread", "brick", "bridge",
	"broom", "brush", "bucket", "building", "bulb", "bulldozer", "bus", "butter",
	"button", "cabinet", "cable", "cactus", "cage", "cake", "calculator", "calendar",
	"camera", "candle", "candy", "canoe", "canvas", "cap", "car", "card",
	"carpet", "carrot", "cart", "castle", "chain", "chair", "chalk", "chart",
	"cheese", "cherry", "chess", "chest", "chimney", "chip", "chocolate", "church",
	"circle", "clay", "cliff", "clock", "cloud", "clover", "club", "coach",
	"coal", "coat", "coconut", "coffee", "coin", "collar", "comb", "compass",
	"computer", "cone", "cookie", "copper", "corn", "couch", "counter", "crayon",
	"cream", "cricket", "cross", "crown", "crystal", "cube", "cup", "curtain",
	"cushion", "dagger", "daisy", "dam", "dart", "desk", "diamond", "diary",
	"dice", "dictionary", "dish", "doll", "dollar", "door", "doughnut", "drawer",
	"dress", "drill", "drum", "duck", "dumbbell", "dust", "dynamite", "ear",
	"earth", "easel", "echo", "egg", "elbow", "electricity", "elephant", "elevator",
	"emerald", "engine", "envelope", "eraser", "escalator", "eye", "eyeglasses", "fabric",

	// Tech & Digital
	"algorithm", "binary", "byte", "cache", "cloud", "code", "cursor", "data",
	"debug", "deploy", "digital", "download", "email", "encrypt", "firewall", "github",
	"hacker", "internet", "kernel", "laptop", "matrix", "network", "online", "pixel",
	"protocol", "query", "router", "script", "server", "software", "terminal", "upload",
	"virtual", "website", "wifi", "xml", "zip", "backup", "browser", "compile",

	// Colors
	"amber", "azure", "beige", "bronze", "crimson", "emerald", "fuchsia", "gold",
	"indigo", "ivory", "jade", "khaki", "lavender", "magenta", "navy", "olive",
	"plum", "ruby", "scarlet", "teal", "violet", "white", "yellow", "zinc",

	// Space & Science
	"asteroid", "aurora", "cosmos", "eclipse", "galaxy", "meteor", "nebula", "orbit",
	"planet", "quantum", "rocket", "satellite", "solar", "telescope", "universe", "venus",
	"atom", "carbon", "element", "fusion", "gravity", "hydrogen", "ion", "laser",
	"molecule", "neutron", "oxygen", "proton", "radiation", "spectrum", "vacuum", "wave",

	// Food & Drinks
	"avocado", "bagel", "coffee", "donut", "espresso", "falafel", "guacamole", "honey",
	"ice", "juice", "kiwi", "lemon", "mango", "noodle", "orange", "pasta",
	"quinoa", "ramen", "salad", "taco", "vanilla", "waffle", "yogurt", "zucchini",

	// Music & Arts
	"accordion", "bass", "cello", "drums", "echo", "flute", "guitar", "harp",
	"jazz", "keyboard", "lyre", "melody", "note", "opera", "piano", "quartet",
	"rhythm", "symphony", "tempo", "violin", "waltz", "xylophone", "yodel", "zither",

	// Weather & Nature
	"blizzard", "breeze", "climate", "dew", "fog", "hail", "lightning", "mist",
	"rain", "snow", "storm", "thunder", "tornado", "wind", "frost", "sunshine",
	"meadow", "forest", "river", "ocean", "mountain", "valley", "desert", "jungle",

	// Emotions & Actions
	"brave", "calm", "daring", "eager", "fierce", "gentle", "happy", "intense",
	"joyful", "kind", "lively", "merry", "noble", "optimistic", "peaceful", "quick",
	"radiant", "serene", "tranquil", "upbeat", "vibrant", "wise", "zealous", "bold",

	// Transportation
	"bicycle", "canoe", "ferry", "helicopter", "jet", "kayak", "locomotive", "motorcycle",
	"plane", "rocket", "scooter", "submarine", "train", "truck", "yacht", "zeppelin",

	// Sports & Games
	"archery", "baseball", "chess", "darts", "football", "golf", "hockey", "jogging",
	"karate", "lacrosse", "marathon", "ninja", "olympics", "paddle", "quiz", "rugby",
	"soccer", "tennis", "volleyball", "wrestling", "yoga", "boxing", "cricket", "diving",

	// Professions
	"artist", "baker", "chef", "doctor", "engineer", "farmer", "guard", "hunter",
	"judge", "knight", "lawyer", "miner", "nurse", "officer", "pilot", "ranger",
	"sailor", "teacher", "vendor", "writer", "dancer", "musician", "scientist", "designer",

	// Mythical & Fantasy
	"angel", "dragon", "fairy", "giant", "hero", "knight", "legend", "magic",
	"phoenix", "quest", "spell", "titan", "unicorn", "wizard", "crystal", "potion",

	// Abstract Concepts
	"balance", "courage", "dream", "energy", "freedom", "harmony", "insight", "justice",
	"knowledge", "liberty", "motion", "order", "power", "quality", "reason", "spirit",
	"truth", "unity", "value", "wisdom", "wonder", "vision", "strength", "grace",
}
