# ☁️ Cloud Security Platform – Architectuur Overzicht

Dit document beschrijft de technische architectuur van ons cloud security platform, geïnspireerd op oplossingen zoals Wiz en Orca Security.  
Het platform analyseert klantomgevingen in AWS op risico’s, misconfiguraties en beveiligingsproblemen via een agentless scanner.

## 🗺️ Architectuurdiagram

<p align="center">
  <img src="./docs/images/ArchitectuurNiagaros.png" width="80%" alt="Architectuurdiagram Niagaros">
</p>

<p align="center"><em>Figuur 1: Overzicht van de Niagaros Cloud Security Architectuur</em></p>

## Lambda Scanner
De **Lambda Scanner** is het hart van de scan-engine.  
Deze functie voert periodieke of on-demand scans uit bij klantomgevingen via **AWS STS AssumeRole** om tijdelijke toegang te verkrijgen.  
De Lambda haalt metadata op van cloudresources (S3, EC2, IAM, etc.) en zet deze om in gestructureerde data.  
De resultaten worden doorgestuurd naar DynamoDB voor analyse en rapportage.

---

## Amazon API Gateway
De **API Gateway** fungeert als de beveiligde ingang van de backend.  
Het ontvangt verzoeken vanuit de frontend (zoals "start scan" of "haal resultaten op") en routeert ze naar de juiste Lambda-functies.  
Daarnaast verzorgt het authenticatie, throttling, logging en requestvalidatie.  
Dit zorgt voor schaalbare en veilige communicatie tussen frontend en backend.

---

## Externe AWS (Klantomgeving)
De **klantomgeving** bevat de AWS-resources die worden geanalyseerd.  
Onze Lambda Scanner gebruikt tijdelijke STS-credentials om in te loggen via een trust policy.  
Er worden enkel **read-only** API-calls uitgevoerd (geen wijzigingen).  
Zo blijft de klantomgeving volledig veilig en controleerbaar.

---

## AWS IAM (Assume Role + Permissions)
De klant maakt een **IAM Role** aan met beperkte leesrechten.  
Deze Role vertrouwt uitsluitend ons AWS-account via een trust policy.  
Onze Lambda gebruikt **AssumeRole** om tijdelijke toegang te krijgen en voert daarna de scans uit.  
Geen permanente sleutels of agenten zijn nodig.

---

## AWS Resources (S3, EC2, VPC, RDS, enz.)
Dit zijn de daadwerkelijke componenten die worden gecontroleerd.  
De Scanner bekijkt configuraties, permissies en security settings van deze resources.  
Risico’s zoals open S3-buckets of zwakke IAM-policies worden gedetecteerd.  
De ruwe scanresultaten worden vervolgens verwerkt door een tweede Lambda.

---

## DynamoDB
**DynamoDB** slaat alle verwerkte scanresultaten en risico’s op.  
De database is snel, serverless en ideaal voor real-time dashboards.  
Elk record bevat informatie zoals resource-ID, tenant-ID, ernst, en detectietijd.  
Hieruit kan de frontend direct inzichten halen zonder zware queries.

---

## Lambda (Data Processing)
Deze **verwerkings-Lambda** filtert, classificeert en prioriteert scanresultaten.  
Hij verrijkt data met context (bijv. “critical” of “compliant”).  
De functie schrijft de opgeschoonde data naar DynamoDB.  
Zo blijft de dataset overzichtelijk en bruikbaar voor rapportage en visualisatie.

---

## GitHub + CI/CD Pipeline
De codebase staat in **GitHub** en wordt automatisch gedeployed via een **CI/CD-pijplijn** (AWS CodePipeline of GitHub Actions).  
Elke wijziging triggert automatische tests en builds.  
Succesvolle builds worden direct gedeployed naar de AWS-omgeving.  
Dit garandeert snelle iteraties en veilige releases.

---

## Amplify (Domain Hosting)
**AWS Amplify** host de frontend webapplicatie en koppelt deze aan een domein.  
Het biedt automatische builds, HTTPS-beveiliging en versiebeheer via GitHub-integratie.  
Amplify zorgt dat de webapp altijd up-to-date is met de laatste backendfunctionaliteit.  
Het is de centrale interface voor klanten om risico’s en rapportages te bekijken.

---

## AWS Cognito (User Database)
**Cognito** regelt gebruikersauthenticatie en -autorisatie.  
Gebruikers loggen in via e-mail of Single Sign-On (bijv. Google of Microsoft).  
Cognito genereert beveiligde JWT-tokens voor API-verificatie.  
Het zorgt ervoor dat alleen geautoriseerde gebruikers toegang hebben tot hun data.

---

## Front-end Web (Dashboard)
De **frontend webapp** is gebouwd in React of Next.js en toont risico-analyses en compliance-statussen.  
Het haalt gegevens op via API Gateway en visualiseert deze met interactieve grafieken.  
Klanten kunnen scans starten, resultaten filteren en rapporten exporteren.  
De frontend communiceert uitsluitend via beveiligde HTTPS-verbindingen.

---

## Amazon CloudWatch (Monitoring & Debugging)
**CloudWatch** verzamelt logs, metrics en alarmen van alle AWS-componenten.  
Het helpt bij het monitoren van prestaties, foutopsporing en uptime-bewaking.  
Automatische alerts signaleren problemen of mislukte scans direct.  
Essentieel voor stabiliteit, debugging en incident response.

---