// This file is part of Ytl.
//
// Ytl is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// Ytl is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Package transports contatin implementations of [static.Transport] interface
package transports

import (
	"github.com/Yggdrasil-Unofficial/ytl/static"
)

// Returns default slice of transports
// (contains all builtin realisations)
func DEFAULT_TRANSPORTS() []static.Transport {
	return []static.Transport{
		TcpTransport{},
	}
}
