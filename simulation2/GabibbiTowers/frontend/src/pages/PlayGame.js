import { useEffect, useState } from 'react';
import { Tower } from './Tower';
import { Form, Row, Col, Container } from 'react-bootstrap';

export const PlayGame = () => {
    const [gameid, setGameid] = useState([]);
    const [tower1, setTower1] = useState([]);
    const [tower2, setTower2] = useState([]);
    const [isWin, setIsWin] = useState(false);
    const [isLost, setIsLost] = useState(false);
    const [[currentFloor1, currentFloor2, isRunning], setGameState] = useState([0, 0, false]);
    const [moves, setMoves] = useState([]);
    const [prize, setPrize] = useState('')

    const handleClick = (color) => {
        var newFloor1 = currentFloor1;
        var newFloor2 = currentFloor2;
        if (color === "blue") {
            if (tower1[tower1.length - 1 - currentFloor1]) {
                newFloor1 -= 1;
            }
            if (tower2[tower2.length - 1 - currentFloor2]) {
                newFloor2 -= 1;
            }
            setMoves(moves.concat([1]));
        } else {
            if (!tower1[tower1.length - 1 - currentFloor1]) {
                newFloor1 -= 1;
            }
            if (!tower2[tower2.length - 1 - currentFloor2]) {
                newFloor2 -= 1;
            }
            setMoves(moves.concat([0]));
        }
        setGameState([newFloor1, newFloor2, true]);

    }

    useEffect(() => {
        gameid.length === 40 && fetch(`http://${window.location.hostname}:8000/games/` + gameid, { credentials: "include" }).then(res => res.json()).then(data => {
            if (!data.error) {
                setTower1(data.tower1);
                setTower2(data.tower2);
                setGameState([data.tower1.length - 1, data.tower2.length - 1, true]);
            }
        })
    }, [gameid]);

    useEffect(() => {
        if (isRunning) {
            if (currentFloor1 === 0 && currentFloor2 === 0) {
                setIsWin(true);
                setGameState([currentFloor1, currentFloor2, false]);
                console.log(moves)
                console.log("Win")
            } else if (currentFloor1 < 0 || currentFloor2 < 0) {
                setIsLost(true);
                setGameState([currentFloor1, currentFloor2, false]);
                console.log(moves)
                console.log("Lost");
            }
        }
    }, [currentFloor1, currentFloor2])

    useEffect(() => {
        if (moves.length > 0 && (isWin || isLost)) {
            fetch(`http://${window.location.hostname}:8000/games/play`, {
                method: "POST",
                credentials: "include",
                headers: {
                    'Content-Type': 'application/json'
                },
                mode: 'cors',
                body: JSON.stringify({
                    id: gameid,
                    moves: moves
                })
            }).then(res => res.json())
                .then(data => {
                    if (!data.error) {
                        if (data.result === "You won!") {
                            fetch(`http://${window.location.hostname}:8000/games/merge`, {
                                method: "POST",
                                credentials: "include",
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                mode: 'cors',
                                body: JSON.stringify({
                                    id: gameid,
                                    public: data.public,
                                    partial_p: data.partial_p
                                })
                            }).then(res => res.json()).then(data2 => {
                                fetch(`http://10.10.0.4:8001/games/${gameid}/${data.public}/redeem`, {
                                    method: "POST",
                                    headers: {
                                        'Content-Type': 'application/json'
                                    },
                                    mode: 'cors',
                                    body: JSON.stringify({
                                        secret: data2.secret,
                                        amount: 1
                                    })
                                }).then(res => res.json()).then(data3 => {
                                    fetch(`http://${window.location.hostname}:8000/games/redeem`, {
                                        method: "POST",
                                        credentials: "include",
                                        headers: {
                                            'Content-Type': 'application/json'
                                        },
                                        mode: 'cors',
                                        body: JSON.stringify({
                                            id: gameid,
                                            public: data.public,
                                            tickets: [
                                                data3.tickets[0]
                                            ],
                                            signature: data3.signature
                                        })
                                    }).then(res => res.json()).then(prize => {
                                        setPrize(prize.prize);
                                    })
                                })
                            })
                        }
                    }
                })
        }
    }, [moves, isWin, isLost])

    return (
        <>
            <Container>
                <Form onSubmit={() => { }}>
                    <Form.Group as={Row} className="mb-3 mt-3">
                        <Form.Label column sm="2">
                            Game Id
                        </Form.Label>
                        <Col sm="10">
                            <Form.Control placeholder="game id" onChange={(e) => setGameid(e.target.value)} />
                        </Col>
                    </Form.Group>
                </Form>
            </Container>
            <div>
                {!tower1 ? <div>Game does not exist</div> :
                    <div style={{ width: "100%", height: "85vh", display: "flex", overflowY: "scroll" }}>
                        <Tower levels={tower1} currentFloor={currentFloor1} />
                        <Tower levels={tower2} currentFloor={currentFloor2} />
                    </div>
                }
                <div style={{ margin: "auto", textAlign: "center" }}>
                    {isWin ? "You Won" : ""}
                    {isLost ? "You Lost" : ""}
                </div>
                <div style={{ margin: "auto", textAlign: "center" }}>
                    {prize}
                </div>
                <div style={{ position: "absolute", bottom: 10, left: "300px", right: "300px", display: "flex" }}>
                    <button disabled={!isRunning} onClick={() => handleClick("blue")} style={{ backgroundColor: "blue", marginLeft: "auto", marginRight: "auto", color: "white" }}>blue</button>
                    <button disabled={!isRunning} onClick={() => handleClick("red")} style={{ backgroundColor: "red", marginLeft: "auto", marginRight: "auto", color: "white" }}>red</button>
                </div>
            </div>
        </>
    )
}