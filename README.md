# KMS with AES-256-GCM: Because Who Needs Sanity?

Welcome to a Key Management System nobody asked for—built in Go, secured with AES-256-GCM, integrated with MongoDB, and sprinkled with Firebase Auth magic. If you're here, you're probably harboring a deep mistrust of the phrase "just use a cloud provider."

## ☂ Overview
Imagine your secrets in a fortress with lasers and rabid guard dogs (not the cute ones). This KMS:
- **Uses AES-256-GCM** like a bouncer who never sleeps.
- **Rotates master keys** so old keys die off faster than your coffee supply.
- **Stores DEKs in Mongo** to keep your plaintext keys about as safe as they can be.
- **Authenticates** with Firebase, because nothing says trust like outsourcing your sign-ins.
- **Requires roles** for each endpoint: `ADMIN`, `SERVICE`, etc.

## 🏗 Architecture at a Glance
- **Master Keys**: The all-powerful overlords of your encryption domain. Rotated periodically so you don’t cry yourself to sleep when a key is compromised.
- **Data Encryption Keys (DEKs)**: Disposable minions generated for each encryption job, stored encrypted in MongoDB so nobody accidentally saves them in Slack.
- **Go Microservice**: A tiny, speedy Gophers-run operation that orchestrates everything with concurrency and occasional existential dread.
- **Endpoints**:
  - **/generate-data-key**: Because you always need more ephemeral keys lying around. Generates a DEK and tucks it away in Mongo.
  - **/encrypt**: Takes your JSON data and, well, does exactly that. Then returns a big scary ciphertext blob.
  - **/decrypt**: The un-encryption experience. Reverts that blob back to readable JSON. Magic.
  - **/rotate-master-key**: Issues a brand-new master key and declares it King. Old keys remain for decrypting older stuff until you decide to bury them forever.
  - **/delete-data-key**: Because not all DEKs deserve immortality. Removes the DEK from the system with a vengeance.
- **Role-Based Access Control**: 
  - `ADMIN` can do all the destructive and terrifying things (like rotating keys or deleting them). 
  - `SERVICE` can generate and use DEKs but can’t dethrone the master key. 
  - `AUDITOR`... let’s just say they get to watch and judge silently.

## 🔑 Key Features
1. **AES-256-GCM**: Authenticated encryption so nobody tampers with your data behind your back.
2. **MongoDB**: For stashing those encrypted DEKs. Because if you’re gonna be paranoid, might as well have a robust document store.
3. **Firebase Authentication**: We absolutely needed an excuse to throw Google somewhere in the mix.
4. **Secure Endpoints**: Protected by TLS to keep the eavesdroppers out.
5. **Master Key Rotation**: Let’s you sleep at night—unless something breaks at 2 AM. Then it’s your problem.
6. **Ditchable DEKs**: Fire them at will when they’re no longer needed.

## 🚧 Setup & Deployment
1. **Set your environment variables** (like `MONGO_URI`, `MASTER_KEYS`, `FIREBASE_SERVICE_ACCOUNT_PATH`) in a `.env` or your preferred meltdown method.
2. **Launch the service** over TLS. 
3. **Pray** you didn’t miss anything in your `.gitignore` when pushing to GitHub.

## 🤖 Testing & Validation
- Use your favorite HTTP tool (hello, Postman) to call each endpoint.
- Ensure your Firebase token is valid and your user role is correct—or prepare to meet the dreaded 403.
- Rotate keys periodically, or whenever you crave a panic-induced adrenaline rush.

## ☕ Final Words
Because apparently I hadn’t suffered enough debugging cryptic logs at 2 AM, I spent **35+ hours** crafting this masterpiece in Go. Hope it saves you from your own meltdown—or at least entertains you while you have one. Cheers to encrypted secrets and questionable life choices.

# Debaraj---
