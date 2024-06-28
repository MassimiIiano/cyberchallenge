import React, { useState } from "react";
import { Container, Col, Row, Form, Button } from "react-bootstrap";

export const CreateGame = () => {
    const [initialization_secret, setInitializationSecret] = useState('');
    const [first_prize, setFirstPrize] = useState('');
    const [partial_prize, setPartialPrize] = useState('');
    const [tower1, setTower1] = useState('');
    const [tower2, setTower2] = useState('');
    const [error, setError] = useState('');
    const [gameid, setGameid] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        fetch(`http://${window.location.hostname}:8000/games`, {
            method: "POST",
            mode: "cors",
            credentials: "include",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                initialization_secret: initialization_secret,
                first_prize: first_prize,
                partial_prize: partial_prize,
                tower1: tower1.split(' ').join('').split(',').map(Number),
                tower2: tower2.split(' ').join('').split(',').map(Number)
            })
        }).then(res => res.json()).then(data => {
            if ('error' in data) {
                setError(data.error);
            }
            else {
                setError('');
                if ('id' in data) {
                    setGameid(`Game successfuly created! Id is: ${data.id}`);
                }
            }
        });
    }

    return (
        <Container>
            <Form onSubmit={handleSubmit}>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Initialization Secret
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="game initialization_secret" onChange={(e) => setInitializationSecret(e.target.value)} />
                    </Col>
                </Form.Group>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        First Prize
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="first prize" onChange={(e) => setFirstPrize(e.target.value)} />
                    </Col>
                </Form.Group>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Partial Prize
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="partial prize" onChange={(e) => setPartialPrize(e.target.value)} />
                    </Col>
                </Form.Group>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Tower 1
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="tower 1" onChange={(e) => setTower1(e.target.value)} />
                    </Col>
                </Form.Group>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Tower 2
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="tower 2" onChange={(e) => setTower2(e.target.value)} />
                    </Col>
                </Form.Group>
                <Button type="submit">Submit</Button>
                <Row style={{ color: "red" }}>
                    {error}
                </Row>
                <Row style={{ color: "green" }}>
                    {gameid}
                </Row>
            </Form>
        </Container>
    )
}