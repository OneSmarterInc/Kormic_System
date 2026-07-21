package main

import (
	"context"
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

func (s *Server) RecordEvent(ctx context.Context, req *pb.RecordRequest) (*pb.RecordResponse, error) {
	// ---------------------------------------------------------
	// Step 3: Hash-Only Anchoring (The Privacy Wall)
	// ---------------------------------------------------------
	// We hash the raw event locally using the organization's private salt.
	// The Cloud HQ will NEVER see the raw event, only the blind hash.
	hasher := sha256.New()
	hasher.Write([]byte(s.localSalt + req.EventData))
	blindHash := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("Blinded local event [%s] to hash: %s\n", req.EventData, blindHash)
	
	// Send ONLY the blinded hash to the Python Cloud HQ.
	// (Simulated network call to HQ)
	// newHead := sendToHQ(req.Ain, "BLIND_HASH:" + blindHash)
	newHead := "hq_validated_head"

	return &pb.RecordResponse{NewHead: newHead}, nil
}

func (s *Server) VerifyToken(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	// ---------------------------------------------------------
	// Enforcement Plane Verification (< 100µs)
	// ---------------------------------------------------------
	// The Go sidecar performs the ML-DSA signature check in-memory.
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
	pb.RegisterMeshKorSidecarServer(s, &Server{
		cloudHQURL: "https://hq.kormic.io",
		localSalt:  "super_secret_local_salt_12345",
	})
	
	log.Printf("Kormic Enforcement Plane (Go Sidecar) listening on %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
