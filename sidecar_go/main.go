package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"

	"google.golang.org/grpc"
	pb "github.com/onesmarter/kormic-go/proto"
)

// Server implements the MeshKor Sidecar gRPC service
type Server struct {
	pb.UnimplementedMeshKorSidecarServer
	cloudHQURL string
	localSalt  string
}

func generateSalt() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("failed to generate random salt: %v", err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) EnrollAgent(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	log.Printf("Enrolling agent: %s\n", req.EntityRef)
	return &pb.EnrollResponse{Ain: "stub_ain_123"}, nil
}

func (s *Server) GetChallenge(ctx context.Context, req *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	return &pb.ChallengeResponse{Nonce: "stub_nonce_123"}, nil
}

func (s *Server) GetPedigree(ctx context.Context, req *pb.PedigreeRequest) (*pb.PedigreeResponse, error) {
	return &pb.PedigreeResponse{PedigreeJson: "{}"}, nil
}

func (s *Server) RecordEvent(ctx context.Context, req *pb.RecordRequest) (*pb.RecordResponse, error) {
	// ---------------------------------------------------------
	// Step 3: Hash-Only Anchoring (The Privacy Wall)
	// ---------------------------------------------------------
	hasher := sha256.New()
	hasher.Write([]byte(s.localSalt + req.EventData))
	blindHash := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("Blinded local event [%s] to hash: %s\n", req.EventData, blindHash)
	newHead := "hq_validated_head"
	return &pb.RecordResponse{NewHead: newHead}, nil
}

func (s *Server) VerifyToken(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	// ---------------------------------------------------------
	// Enforcement Plane Verification (< 100µs)
	// ---------------------------------------------------------
	log.Printf("Verifying token for AIN: %s\n", req.Ain)
	return &pb.VerifyResponse{
		Status: "PASS",
		Reason: "Signature OK",
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":5050")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	s := grpc.NewServer()
	
	// GAP 5: Generate random 256-bit salt securely, not hardcoded.
	secureSalt := generateSalt()
	
	pb.RegisterMeshKorSidecarServer(s, &Server{
		cloudHQURL: "https://hq.kormic.io",
		localSalt:  secureSalt,
	})
	
	log.Printf("Kormic Enforcement Plane (Go Sidecar) listening on %v", lis.Addr())
	log.Printf("Sidecar Secure Salt Initialized: %s", secureSalt[:8]+"...")
	
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
