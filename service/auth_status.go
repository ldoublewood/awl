package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pProtocol "github.com/libp2p/go-libp2p/core/protocol"

	"github.com/anywherelan/awl/awldns"
	"github.com/anywherelan/awl/awlevent"
	"github.com/anywherelan/awl/config"
	"github.com/anywherelan/awl/protocol"
)

const (
	backgroundExchangeStatusInfoInterval = 5 * time.Minute
	backgroundRetryAuthRequests          = 5 * time.Minute
)

type P2p interface {
	ConnectPeer(ctx context.Context, peerID peer.ID) error
	NewStream(ctx context.Context, id peer.ID, proto libp2pProtocol.ID) (network.Stream, error)
	NewStreamWithDedicatedConn(ctx context.Context, id peer.ID, proto libp2pProtocol.ID) (network.Stream, error)
	SubscribeConnectionEvents(onConnected, onDisconnected func(network.Network, network.Conn))
	ProtectPeer(id peer.ID)
}

type AuthStatus struct {
	ingoingAuths  map[peer.ID]protocol.AuthPeer
	outgoingAuths map[peer.ID]protocol.AuthPeer
	authsLock     sync.RWMutex
	logger        *log.ZapEventLogger
	p2p           P2p
	conf          *config.Config
	authsEmitter  awlevent.Emitter
}

func NewAuthStatus(p2pService P2p, conf *config.Config, eventbus awlevent.Bus) *AuthStatus {
	emitter, err := eventbus.Emitter(new(awlevent.ReceivedAuthRequest))
	if err != nil {
		panic(err)
	}

	auth := &AuthStatus{
		ingoingAuths:  make(map[peer.ID]protocol.AuthPeer),
		outgoingAuths: make(map[peer.ID]protocol.AuthPeer),
		logger:        log.Logger("awl/service/status"),
		p2p:           p2pService,
		conf:          conf,
		authsEmitter:  emitter,
	}
	auth.restoreOutgoingAuths()
	p2pService.SubscribeConnectionEvents(auth.onPeerConnected, auth.onPeerDisconnected)
	return auth
}

func (s *AuthStatus) StatusStreamHandler(stream network.Stream) {
	defer func() {
		_ = stream.Close()
	}()

	remotePeer := stream.Conn().RemotePeer()
	peerID := remotePeer.String()
	knownPeer, known := s.conf.GetPeer(peerID)
	_, isBlocked := s.conf.GetBlockedPeer(peerID)
	if !known && !isBlocked {
		s.logger.Infof("Unknown peer %s tried to exchange status info", peerID)
		return
	}

	// Receiving info
	oppositePeerInfo, err := protocol.ReceiveStatus(stream)
	if err != nil {
		s.logger.Errorf("receiving status info from %s: %v", peerID, err)
		return
	}
	s.authsLock.Lock()
	delete(s.outgoingAuths, remotePeer)
	s.authsLock.Unlock()

	ip, _, errParse := net.ParseCIDR(s.conf.VPNConfig.IPNet)
	if errParse != nil {
		s.logger.Errorf("invalid ip address %s", s.conf.VPNConfig.IPNet)
		return
	}
	ipStr := ip.To4().String()

	// Sending info
	myPeerInfo := s.createPeerInfo(knownPeer, s.conf.P2pNode.Name, ipStr, isBlocked)
	err = protocol.SendStatus(stream, myPeerInfo)
	if err != nil {
		s.logger.Errorf("sending status info to %s as an answer: %v", peerID, err)
	}

	s.logger.Infof("successfully exchanged status info with %s (%s)", knownPeer.DisplayName(), peerID)
	if isBlocked {
		return
	}
	// Processing opposite peer info

	// get the latest peer config to reduce race time between get and upsert (without locking)
	// TODO: fix race completely
	knownPeer, _ = s.conf.GetPeer(peerID)
	newPeer := s.processPeerStatusInfo(knownPeer, oppositePeerInfo)
	s.conf.UpsertPeer(newPeer)
}

func (s *AuthStatus) ExchangeNewStatusInfo(ctx context.Context, remotePeerID peer.ID, knownPeer config.KnownPeer) error {
	s.authsLock.Lock()
	delete(s.ingoingAuths, remotePeerID)
	s.authsLock.Unlock()

	err := s.p2p.ConnectPeer(ctx, remotePeerID)
	if err != nil {
		return err
	}

	stream, err := s.p2p.NewStream(ctx, remotePeerID, protocol.GetStatusMethod)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Close()
	}()

	_, isBlocked := s.conf.GetBlockedPeer(remotePeerID.String())
	ip, _, errParse := net.ParseCIDR(s.conf.VPNConfig.IPNet)
	if errParse != nil {
		return fmt.Errorf("invalid ip address %s", s.conf.VPNConfig.IPNet)
	}
	ipStr := ip.To4().String()

	myPeerInfo := s.createPeerInfo(knownPeer, s.conf.P2pNode.Name, ipStr, isBlocked)
	err = protocol.SendStatus(stream, myPeerInfo)
	if err != nil {
		return fmt.Errorf("sending status info: %v", err)
	}

	oppositePeerInfo, err := protocol.ReceiveStatus(stream)
	if err != nil {
		return fmt.Errorf("receiving status info: %v", err)
	}

	if isBlocked {
		return nil
	}

	// get the latest peer config to reduce race time between get and upsert (without locking)
	// TODO: fix race completely
	knownPeer, _ = s.conf.GetPeer(remotePeerID.String())
	newPeer := s.processPeerStatusInfo(knownPeer, oppositePeerInfo)
	s.conf.UpsertPeer(newPeer)

	return nil
}

func (s *AuthStatus) BlockPeer(peerID peer.ID, name string) {
	s.conf.UpsertBlockedPeer(peerID.String(), name)
	go func() {
		errExchange := s.ExchangeNewStatusInfo(context.Background(), peerID, config.KnownPeer{})
		if errExchange != nil {
			s.logger.Errorf("exchange new status info %s: %v", peerID.String(), errExchange)
		}
	}()
}

func (s *AuthStatus) createPeerInfo(peer config.KnownPeer, myPeerName, ipAddr string, declined bool) protocol.PeerStatusInfo {
	if declined {
		return protocol.PeerStatusInfo{
			Declined: true,
		}
	}
	myPeerInfo := protocol.PeerStatusInfo{
		Name:                 myPeerName,
		IPAddr:               ipAddr,
		AllowUsingAsExitNode: peer.WeAllowUsingAsExitNode,
	}

	return myPeerInfo
}

func (s *AuthStatus) processPeerStatusInfo(peer config.KnownPeer, peerInfo protocol.PeerStatusInfo) config.KnownPeer {
	peer.LastSeen = time.Now()
	if peerInfo.Declined {
		peer.Declined = true
		return peer
	}
	peer.Name = peerInfo.Name
	peer.IPAddr = peerInfo.IPAddr
	peer.Confirmed = true
	peer.Declined = false
	if peer.DomainName == "" {
		peer.DomainName = awldns.TrimDomainName(peer.DisplayName())
	}
	if peer.Alias == "" {
		peer.Alias = s.conf.GenUniqPeerAlias(peer.Name, peer.Alias)
	}
	peer.AllowedUsingAsExitNode = peerInfo.AllowUsingAsExitNode

	return peer
}

func (s *AuthStatus) AuthStreamHandler(stream network.Stream) {
	defer func() {
		_ = stream.Close()
	}()

	remotePeer := stream.Conn().RemotePeer()
	peerID := remotePeer.String()
	authPeer, err := protocol.ReceiveAuth(stream)
	if err != nil {
		s.logger.Errorf("receiving auth from %s: %v", peerID, err)
		return
	}

	key := config.GetHmacKey()
	// peerID is remote peer ID, but from signing (remote) side's point of view,  peerID is my ID, similar for my peer ID
	verified, message, errCheck := protocol.CheckAuthInfo(authPeer.AuthInfo, peerID, s.conf.P2pNode.PeerID, nil, key)
	if errCheck != nil {
		s.logger.Errorf("check auth info, peerID: %s, message: %s, err: %v", peerID, message, err)
	}
	if !verified {
		s.logger.Errorf("signature auth info not verified, peerID:%s, message: %s, err: %v", peerID, message, err)
	}

	_, isBlocked := s.conf.GetBlockedPeer(peerID)
	_, confirmed := s.conf.GetPeer(peerID)
	s.conf.RLock()
	autoAccept := s.conf.P2pNode.AutoAcceptAuthRequests
	s.conf.RUnlock()

	if !confirmed && !isBlocked && !autoAccept {
		s.authsLock.Lock()
		s.ingoingAuths[remotePeer] = authPeer
		s.authsLock.Unlock()
		_ = s.authsEmitter.Emit(awlevent.ReceivedAuthRequest{
			AuthPeer: authPeer,
			PeerID:   peerID,
		})
	}
	if !confirmed && !isBlocked && autoAccept {
		defer func() {
			s.AddPeer(context.Background(), remotePeer, authPeer.Name, s.conf.GenUniqPeerAlias(authPeer.Name, ""), true)
		}()
	}

	authInfo, message, err := protocol.GenAuthInfo(s.conf.P2pNode.PeerID, peerID, &authPeer.Nonce, key)
	if err != nil {
		s.logger.Errorf("gen auth info for response %s: %v", peerID, err)
	}
	s.logger.Debugf("gen auth info, message: %s", message)

	authResponse := protocol.AuthPeerResponse{AuthInfo: authInfo, Confirmed: confirmed, Declined: isBlocked || !verified}
	err = protocol.SendAuthResponse(stream, authResponse)
	if err != nil {
		s.logger.Errorf("sending auth response to %s as an answer: %v", peerID, err)
		return
	}

	s.logger.Infof("Successfully received auth from %s (%s)", authPeer.Name, peerID)
}

func (s *AuthStatus) SendAuthRequest(ctx context.Context, peerID peer.ID, req protocol.AuthPeer) error {
	s.authsLock.Lock()
	s.outgoingAuths[peerID] = req
	s.authsLock.Unlock()

	err := s.p2p.ConnectPeer(ctx, peerID)
	if err != nil {
		return err
	}

	stream, err := s.p2p.NewStream(ctx, peerID, protocol.AuthMethod)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Close()
	}()

	err = protocol.SendAuth(stream, req)
	if err != nil {
		return fmt.Errorf("sending auth: %v", err)
	}

	authResponse, err := protocol.ReceiveAuthResponse(stream)
	if err != nil {
		return fmt.Errorf("receiving auth response from %s: %v", peerID, err)
	}

	key := config.GetHmacKey()
	// peerID is remote peer ID, but from signing (remote) side's point of view,  peerID is my ID, similar for my peer ID
	// remote nonce (from remote side's point of view) here actually is the nonce of AuthRequest
	verified, message, errCheck := protocol.CheckAuthInfo(authResponse.AuthInfo, peerID.String(), s.conf.P2pNode.PeerID, &req.Nonce, key)
	s.logger.Debugf("gen auth info, message: %s", message)
	if errCheck != nil {
		s.logger.Errorf("check auth info %s: %v", peerID, err)
		return errCheck
	}
	if !verified {
		s.logger.Errorf("signature auth info not verified %s: %v", peerID, err)
		return fmt.Errorf("signature auth info not verified %s: %v", peerID, err)
	}

	if authResponse.Confirmed || authResponse.Declined {
		s.authsLock.Lock()
		delete(s.outgoingAuths, peerID)
		s.authsLock.Unlock()
	}
	if authResponse.Declined {
		knownPeer, exists := s.conf.GetPeer(peerID.String())
		if exists {
			knownPeer.Declined = true
			s.conf.UpsertPeer(knownPeer)
		}
	}

	s.logger.Infof("Successfully send auth to %s", peerID)
	return nil
}

func (s *AuthStatus) AddPeer(ctx context.Context, peerID peer.ID, name, uniqAlias string, confirmed bool) {
	s.conf.RLock()
	//ipAddr := s.conf.GenerateNextIpAddr()
	s.conf.RUnlock()
	newPeerConfig := config.KnownPeer{
		PeerID: peerID.String(),
		Name:   name,
		Alias:  uniqAlias,
		//IPAddr:    ipAddr,
		Confirmed: confirmed,
		CreatedAt: time.Now(),
	}
	newPeerConfig.DomainName = awldns.TrimDomainName(newPeerConfig.DisplayName())
	s.conf.RemoveBlockedPeer(peerID.String())
	s.conf.UpsertPeer(newPeerConfig)
	s.p2p.ProtectPeer(peerID)

	go func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if !confirmed {
			key := config.GetHmacKey()
			authInfo, message, err := protocol.GenAuthInfo(s.conf.P2pNode.PeerID, peerID.String(), nil, key)
			if err != nil {
				s.logger.Errorf("gen auth info %s: %v", peerID.String(), err)
			}
			s.logger.Debugf("gen auth info, message: %s", message)

			authPeer := protocol.AuthPeer{
				AuthInfo: authInfo,
				Name:     s.conf.P2pNode.Name,
			}
			errAuth := s.SendAuthRequest(ctx, peerID, authPeer)
			if errAuth != nil {
				s.logger.Errorf("send auth request %s: %v", peerID.String(), err)
				//stop more action
				return
			}
		}

		knownPeer, _ := s.conf.GetPeer(peerID.String())
		errExchange := s.ExchangeNewStatusInfo(ctx, peerID, knownPeer)
		if errExchange != nil {
			s.logger.Errorf("exchange new status info %s: %v", peerID.String(), errExchange)
		}

	}()
}

func (s *AuthStatus) ExchangeStatusInfoWithAllKnownPeers(ctx context.Context) {
	s.conf.RLock()
	peers := make([]string, 0, len(s.conf.KnownPeers))
	for peerID := range s.conf.KnownPeers {
		peers = append(peers, peerID)
	}
	s.conf.RUnlock()

	for _, peerID := range peers {
		knownPeer, exists := s.conf.GetPeer(peerID)
		if !exists {
			continue
		}
		errExchange := s.ExchangeNewStatusInfo(ctx, knownPeer.PeerId(), knownPeer)
		if errExchange != nil {
			s.logger.Errorf("exchange new status info %s: %v", knownPeer.PeerID, errExchange)
		}
	}
}

func (s *AuthStatus) BackgroundRetryAuthRequests(ctx context.Context) {
	f := func() {
		s.authsLock.RLock()
		outgoingAuthsCopy := make(map[peer.ID]protocol.AuthPeer, len(s.outgoingAuths))
		for key, val := range s.outgoingAuths {
			outgoingAuthsCopy[key] = val
		}
		s.authsLock.RUnlock()

		for peerID, auth := range outgoingAuthsCopy {
			_ = s.SendAuthRequest(ctx, peerID, auth)
		}
	}

	ticker := time.NewTicker(backgroundRetryAuthRequests)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f()
		}
	}
}

func (s *AuthStatus) BackgroundExchangeStatusInfo(ctx context.Context) {
	ticker := time.NewTicker(backgroundExchangeStatusInfoInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ExchangeStatusInfoWithAllKnownPeers(ctx)
		}
	}
}

func (s *AuthStatus) GetIngoingAuthRequests() map[string]protocol.AuthPeer {
	s.authsLock.RLock()
	defer s.authsLock.RUnlock()

	result := make(map[string]protocol.AuthPeer, len(s.ingoingAuths))
	for peerID, auth := range s.ingoingAuths {
		result[peerID.String()] = auth
	}
	return result
}

func (s *AuthStatus) restoreOutgoingAuths() {
	s.conf.RLock()
	defer s.conf.RUnlock()

	peerName := s.conf.P2pNode.Name
	outgoingAuths := make(map[peer.ID]protocol.AuthPeer)
	for _, knownPeer := range s.conf.KnownPeers {
		if !knownPeer.Confirmed && !knownPeer.Declined {
			key := config.GetHmacKey()
			authInfo, message, err := protocol.GenAuthInfo(s.conf.P2pNode.PeerID, knownPeer.PeerID, nil, key)
			s.logger.Debugf("gen auth info, message: %s", message)
			if err != nil {
				s.logger.Errorf("gen auth info %s: %v", knownPeer.PeerID, err)
				continue
			}

			outgoingAuths[knownPeer.PeerId()] = protocol.AuthPeer{
				AuthInfo: authInfo,
				Name:     peerName,
			}
		}
	}
	s.outgoingAuths = outgoingAuths
}

func (s *AuthStatus) onPeerConnected(_ network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	s.authsLock.RLock()
	authPeer, hasOutgAuth := s.outgoingAuths[peerID]
	s.authsLock.RUnlock()

	knownPeer, known := s.conf.GetPeer(peerID.String())
	if !known && !hasOutgAuth {
		return
	}
	s.conf.UpdatePeerLastSeen(peerID.String())

	go func() {
		if hasOutgAuth {
			err := s.SendAuthRequest(context.Background(), peerID, authPeer)
			if err != nil {
				s.logger.Errorf("send auth to recently connected peer %s: %v", peerID, err)
			}
		}

		if known {
			dir := strings.ToLower(conn.Stat().Direction.String())
			s.logger.Infof("peer '%s' connected, direction %s, address %s", knownPeer.DisplayName(), dir, conn.RemoteMultiaddr())

			err := s.ExchangeNewStatusInfo(context.Background(), peerID, knownPeer)
			if err != nil && knownPeer.Confirmed {
				s.logger.Errorf("exchange status info with recently connected peer %s (%s): %v", knownPeer.DisplayName(), peerID, err)
			}
		}
	}()
}

func (s *AuthStatus) onPeerDisconnected(_ network.Network, conn network.Conn) {
	peerID := conn.RemotePeer()
	knownPeer, known := s.conf.GetPeer(peerID.String())
	if !known {
		return
	}
	s.conf.UpdatePeerLastSeen(peerID.String())
	s.logger.Infof("peer '%s' disconnected, address %s", knownPeer.DisplayName(), conn.RemoteMultiaddr())
}
